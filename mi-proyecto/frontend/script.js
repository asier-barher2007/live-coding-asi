/**
 * F1 STORE — Frontend JavaScript
 * ─────────────────────────────────────────────
 * Arquitectura:
 *   - Estado en memoria (currentUser, cart)
 *   - API calls con fetch + token JWT en header
 *   - Sanitización de todo texto antes de insertarlo en el DOM
 *   - NUNCA se almacena la contraseña ni el hash en cliente
 *   - Limitación de rate en cliente (debounce en búsqueda)
 * ─────────────────────────────────────────────
 */

 'use strict';

 // ══════════════════════════════════════════════════════
 //  CONFIGURACIÓN
 // ══════════════════════════════════════════════════════
 
 // Ruta relativa: las llamadas /api/* las intercepta nginx y las manda al backend.
 // Así no hay errores de CORS y funciona igual en local y en producción.
 const API_BASE = '/api';
 
 // ══════════════════════════════════════════════════════
 //  ESTADO GLOBAL
 // ══════════════════════════════════════════════════════
 
 const state = {
   currentUser: null,   // { id, username, email, balance }
   token: null,         // JWT – sólo en memoria, NO en localStorage
   cart: [],            // [{ product, quantity }]
   products: [],        // caché de productos del catálogo
   currentSection: 'catalog',
 };
 
 // ══════════════════════════════════════════════════════
 //  UTILIDADES DE SEGURIDAD
 // ══════════════════════════════════════════════════════
 
 /**
  * Escapa HTML para evitar XSS al insertar texto en el DOM.
  * Siempre usar esta función antes de .innerHTML
  */
 function escapeHtml(str) {
   if (str === null || str === undefined) return '';
   return String(str)
     .replace(/&/g, '&amp;')
     .replace(/</g, '&lt;')
     .replace(/>/g, '&gt;')
     .replace(/"/g, '&quot;')
     .replace(/'/g, '&#x27;');
 }
 
 /**
  * Sanitiza una URL para evitar javascript: y data: peligrosos
  */
 function safeUrl(url) {
   if (!url) return null;
   const trimmed = String(url).trim();
   if (/^(https?:\/\/)/i.test(trimmed)) return trimmed;
   return null;
 }
 
 /**
  * Construye la cabecera con el token JWT
  */
 function authHeaders() {
   const headers = { 'Content-Type': 'application/json' };
   if (state.token) {
     headers['Authorization'] = `Bearer ${state.token}`;
   }
   return headers;
 }
 
 /**
  * Wrapper seguro para fetch con timeout anti-cuelgue.
  * ⚠️  ESTE BLOQUE ES OBLIGATORIO — no lo borres.
  *     Sin él, todas las llamadas al servidor quedan colgadas
  *     y la página se queda en "Cargando productos..." para siempre.
  */
 async function apiFetch(endpoint, options = {}) {
   const controller = new AbortController();
   // 15 segundos de timeout (da margen al backend para arrancar con Docker)
   const timeout = setTimeout(() => controller.abort(), 15000);
   try {
     const res = await fetch(`${API_BASE}${endpoint}`, {
       ...options,
       headers: { ...authHeaders(), ...(options.headers || {}) },
       signal: controller.signal,
     });
     clearTimeout(timeout);
     // Intentar parsear JSON; si el servidor devuelve HTML (error nginx) capturamos el fallo
     let data;
     try {
       data = await res.json();
     } catch (_) {
       data = { message: 'El servidor devolvió una respuesta inesperada.' };
     }
     return { ok: res.ok, status: res.status, data };
   } catch (err) {
     clearTimeout(timeout);
     if (err.name === 'AbortError') {
       return {
         ok: false, status: 0,
         data: { message: 'El servidor tardó demasiado en responder. Asegúrate de que Docker está corriendo (docker-compose up --build).' },
       };
     }
     return {
       ok: false, status: 0,
       data: { message: 'No se pudo conectar con el servidor. Comprueba que Docker está en marcha.' },
     };
   }
 }
 
 // ══════════════════════════════════════════════════════
 //  VALIDACIONES (lado cliente — el backend también valida)
 // ══════════════════════════════════════════════════════
 
 const validators = {
   email(v) {
     if (!v) return 'El email es obligatorio.';
     if (v.length > 254) return 'Email demasiado largo.';
     if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'Introduce un email válido.';
     return null;
   },
   username(v) {
     if (!v) return 'El nombre de usuario es obligatorio.';
     if (v.length < 3) return 'Mínimo 3 caracteres.';
     if (v.length > 30) return 'Máximo 30 caracteres.';
     if (!/^[a-zA-Z0-9_]+$/.test(v)) return 'Solo letras, números y guión bajo.';
     return null;
   },
   password(v) {
     if (!v || v.trim() === '') return 'La contraseña es obligatoria.';
     if (v.length < 8) return 'Mínimo 8 caracteres.';
     if (v.length > 128) return 'Máximo 128 caracteres.';
     if (!/[A-Z]/.test(v)) return 'Debe incluir al menos una letra mayúscula.';
     if (!/[a-z]/.test(v)) return 'Debe incluir al menos una letra minúscula.';
     if (!/[0-9]/.test(v)) return 'Debe incluir al menos un número.';
     if (!/[^a-zA-Z0-9]/.test(v)) return 'Debe incluir al menos un símbolo (ej: !, @, #, $).';
     return null;
   },
   productName(v) {
     if (!v) return 'El nombre es obligatorio.';
     if (v.trim().length < 3) return 'Mínimo 3 caracteres.';
     if (v.length > 100) return 'Máximo 100 caracteres.';
     return null;
   },
   productDesc(v) {
     if (!v) return 'La descripción es obligatoria.';
     if (v.trim().length < 10) return 'Mínimo 10 caracteres.';
     if (v.length > 500) return 'Máximo 500 caracteres.';
     return null;
   },
   productPrice(v) {
     const n = parseFloat(v);
     if (isNaN(n) || v === '') return 'Introduce un precio válido.';
     if (n <= 0) return 'El precio debe ser mayor que 0.';
     if (n > 99999) return 'Precio demasiado alto.';
     return null;
   },
 };
 
 /** Calcula la fortaleza de la contraseña (0-5) */
 function passwordStrength(pw) {
   let score = 0;
   if (pw.length >= 8)  score++;
   if (pw.length >= 12) score++;
   if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
   if (/[0-9]/.test(pw)) score++;
   if (/[^A-Za-z0-9]/.test(pw)) score++;
   return Math.min(score, 4);
 }
 
 // ══════════════════════════════════════════════════════
 //  TOASTS
 // ══════════════════════════════════════════════════════
 
 function showToast(message, type = 'info', duration = 3500) {
   const container = document.getElementById('toastContainer');
   const toast = document.createElement('div');
   toast.className = `toast ${type}`;
   // Usar textContent para evitar XSS
   toast.textContent = message;
   container.appendChild(toast);
   setTimeout(() => {
     toast.style.animation = 'toastOut 0.3s ease forwards';
     setTimeout(() => toast.remove(), 300);
   }, duration);
 }
 
 // ══════════════════════════════════════════════════════
 //  CONFIRM DIALOG
 // ══════════════════════════════════════════════════════
 
 function showConfirm(title, message) {
   return new Promise((resolve) => {
     const overlay = document.getElementById('modalConfirm');
     document.getElementById('confirmTitle').textContent = title;
     document.getElementById('confirmMessage').textContent = message;
     overlay.classList.remove('hidden');
 
     const btnOk = document.getElementById('btnConfirmOk');
     const btnCancel = document.getElementById('btnConfirmCancel');
 
     const cleanup = (result) => {
       overlay.classList.add('hidden');
       btnOk.replaceWith(btnOk.cloneNode(true));
       btnCancel.replaceWith(btnCancel.cloneNode(true));
       resolve(result);
     };
 
     document.getElementById('btnConfirmOk').addEventListener('click', () => cleanup(true));
     document.getElementById('btnConfirmCancel').addEventListener('click', () => cleanup(false));
   });
 }
 
 // ══════════════════════════════════════════════════════
 //  MODALES
 // ══════════════════════════════════════════════════════
 
 function openModal(id) {
   document.getElementById(id).classList.remove('hidden');
   document.body.style.overflow = 'hidden';
 }
 
 function closeModal(id) {
   document.getElementById(id).classList.add('hidden');
   document.body.style.overflow = '';
 }
 
 // Cerrar modal al hacer click en overlay
 document.querySelectorAll('.modal-overlay').forEach(overlay => {
   overlay.addEventListener('click', (e) => {
     if (e.target === overlay) closeModal(overlay.id);
   });
 });
 
 // Botones cerrar modal
 document.querySelectorAll('.modal-close').forEach(btn => {
   btn.addEventListener('click', () => closeModal(btn.dataset.modal));
 });
 
 // ESC cierra modales
 document.addEventListener('keydown', (e) => {
   if (e.key === 'Escape') {
     ['modalLogin','modalRegister','modalProduct'].forEach(id => {
       if (!document.getElementById(id).classList.contains('hidden')) closeModal(id);
     });
   }
 });
 
 // Switches entre modales
 document.getElementById('switchToRegister').addEventListener('click', (e) => {
   e.preventDefault();
   closeModal('modalLogin');
   openModal('modalRegister');
 });
 document.getElementById('switchToLogin').addEventListener('click', (e) => {
   e.preventDefault();
   closeModal('modalRegister');
   openModal('modalLogin');
 });
 
 // Open modals
 document.getElementById('btnLoginOpen').addEventListener('click', () => openModal('modalLogin'));
 document.getElementById('btnRegisterOpen').addEventListener('click', () => openModal('modalRegister'));
 
 // ══════════════════════════════════════════════════════
 //  NAVEGACIÓN DE SECCIONES (SPA)
 // ══════════════════════════════════════════════════════
 
 const sections = {
   catalog: 'sectionCatalog',
   sell: 'sectionSell',
   'my-orders': 'sectionMyOrders',
   'my-products': 'sectionMyProducts',
 };
 
 function navigate(section) {
   // Sections that require login
   if (['sell', 'my-orders', 'my-products'].includes(section) && !state.currentUser) {
     showToast('Debes iniciar sesión para acceder a esta sección.', 'error');
     openModal('modalLogin');
     return;
   }
 
   state.currentSection = section;
 
   // Ocultar todas las secciones
   Object.values(sections).forEach(id => {
     document.getElementById(id).classList.add('hidden');
   });
 
   // Mostrar la sección activa
   document.getElementById(sections[section]).classList.remove('hidden');
 
   // Actualizar nav links
   document.querySelectorAll('.nav-link').forEach(link => {
     link.classList.toggle('active', link.dataset.section === section);
   });
 
   // Ocultar hero si no es catálogo
   document.getElementById('heroSection').style.display = section === 'catalog' ? '' : 'none';
 
   // Cargar datos necesarios
   if (section === 'catalog') loadProducts();
   if (section === 'my-orders') loadMyOrders();
   if (section === 'my-products') loadMyProducts();
 
   window.scrollTo({ top: 0, behavior: 'smooth' });
 }
 
 // Nav links
 document.querySelectorAll('.nav-link').forEach(link => {
   link.addEventListener('click', (e) => {
     e.preventDefault();
     navigate(link.dataset.section);
   });
 });
 
 // Hero explore button
 document.getElementById('btnExplore').addEventListener('click', () => navigate('catalog'));
 
 // ══════════════════════════════════════════════════════
 //  AUTH — LOGIN
 // ══════════════════════════════════════════════════════
 
 function setFieldError(id, message) {
   const el = document.getElementById(id);
   if (el) el.textContent = message || '';
 }
 
 function clearFormErrors(prefix, fields) {
   fields.forEach(f => setFieldError(`err${prefix}${f}`, ''));
   const global = document.getElementById(`${prefix.toLowerCase()}GlobalError`);
   if (global) global.classList.add('hidden');
 }
 
 document.getElementById('loginForm').addEventListener('submit', async (e) => {
   e.preventDefault();
   clearFormErrors('Login', ['Email', 'Password']);
 
   const email = document.getElementById('loginEmail').value.trim();
   const password = document.getElementById('loginPassword').value;
 
   let hasError = false;
 
   const emailErr = validators.email(email);
   if (emailErr) { setFieldError('errLoginEmail', emailErr); hasError = true; }
 
   if (!password) { setFieldError('errLoginPassword', 'La contraseña es obligatoria.'); hasError = true; }
 
   if (hasError) return;
 
   // Mostrar loader
   const btn = document.getElementById('btnLoginSubmit');
   toggleBtnLoading(btn, true);
 
   const { ok, data } = await apiFetch('/auth/login', {
     method: 'POST',
     body: JSON.stringify({ email, password }),
   });
 
   toggleBtnLoading(btn, false);
 
   if (!ok) {
     const global = document.getElementById('loginGlobalError');
     // Mensaje genérico para no revelar si el email existe
     global.textContent = data.message || 'Credenciales incorrectas. Inténtalo de nuevo.';
     global.classList.remove('hidden');
     return;
   }
 
   // Login exitoso
   state.token = data.token;
   state.currentUser = data.user;
 
   closeModal('modalLogin');
   document.getElementById('loginForm').reset();
   updateAuthUI();
   showToast(`Bienvenido de nuevo, ${escapeHtml(data.user.username)}! 🏎️`, 'success');
   loadProducts();
 });
 
 // ══════════════════════════════════════════════════════
 //  AUTH — REGISTRO
 // ══════════════════════════════════════════════════════
 
 // Password strength indicator
 document.getElementById('regPassword').addEventListener('input', function() {
   const score = passwordStrength(this.value);
   const bar = document.getElementById('pwBar');
   const label = document.getElementById('pwStrengthLabel');
   const colors = ['#ff2222','#ff6622','#ffaa00','#88cc00','#00cc44'];
   const labels = ['','Muy débil','Débil','Aceptable','Fuerte','Muy fuerte'];
   bar.style.width = `${(score/4)*100}%`;
   bar.style.background = colors[score] || colors[0];
   label.textContent = labels[score] || '';
 });
 
 document.getElementById('registerForm').addEventListener('submit', async (e) => {
   e.preventDefault();
   clearFormErrors('Register', ['Username','Email','Password','PasswordConfirm']);
 
   const username = document.getElementById('regUsername').value.trim();
   const email = document.getElementById('regEmail').value.trim();
   const password = document.getElementById('regPassword').value;
   const passwordConfirm = document.getElementById('regPasswordConfirm').value;
 
   let hasError = false;
 
   const usernameErr = validators.username(username);
   if (usernameErr) { setFieldError('errRegUsername', usernameErr); hasError = true; }
 
   const emailErr = validators.email(email);
   if (emailErr) { setFieldError('errRegEmail', emailErr); hasError = true; }
 
   const passwordErr = validators.password(password);
   if (passwordErr) { setFieldError('errRegPassword', passwordErr); hasError = true; }
 
   if (password !== passwordConfirm) {
     setFieldError('errRegPasswordConfirm', 'Las contraseñas no coinciden.');
     hasError = true;
   }
 
   if (hasError) return;
 
   const btn = document.getElementById('btnRegisterSubmit');
   toggleBtnLoading(btn, true);
 
   const { ok, data } = await apiFetch('/auth/register', {
     method: 'POST',
     body: JSON.stringify({ username, email, password }),
   });
 
   toggleBtnLoading(btn, false);
 
   if (!ok) {
     const global = document.getElementById('registerGlobalError');
     global.textContent = data.message || 'Error al crear la cuenta. Inténtalo de nuevo.';
     global.classList.remove('hidden');
     return;
   }
 
   state.token = data.token;
   state.currentUser = data.user;
 
   closeModal('modalRegister');
   document.getElementById('registerForm').reset();
   updateAuthUI();
   showToast(`¡Cuenta creada! Bienvenido al paddock, ${escapeHtml(data.user.username)}! 🏁`, 'success');
   loadProducts();
 });
 
 // ══════════════════════════════════════════════════════
 //  AUTH — LOGOUT
 // ══════════════════════════════════════════════════════
 
 document.getElementById('btnLogout').addEventListener('click', async () => {
   const confirmed = await showConfirm('Cerrar sesión', '¿Quieres cerrar tu sesión?');
   if (!confirmed) return;
 
   state.token = null;
   state.currentUser = null;
   state.cart = [];
 
   updateAuthUI();
   updateCartBadge();
   navigate('catalog');
   showToast('Sesión cerrada. ¡Hasta pronto!', 'info');
 });
 
 // ══════════════════════════════════════════════════════
 //  UI AUTH
 // ══════════════════════════════════════════════════════
 
 function updateAuthUI() {
   const authButtons = document.getElementById('authButtons');
   const userMenu = document.getElementById('userMenu');
   const userGreeting = document.getElementById('userGreeting');
   const userBalance = document.getElementById('userBalance');
 
   if (state.currentUser) {
     authButtons.classList.add('hidden');
     userMenu.classList.remove('hidden');
     userGreeting.textContent = `Hola, ${state.currentUser.username}`;
     userBalance.textContent = `💰 ${formatPrice(state.currentUser.balance || 0)}`;
   } else {
     authButtons.classList.remove('hidden');
     userMenu.classList.add('hidden');
     // Ocultar secciones privadas si estamos en ellas
     if (['sell','my-orders','my-products'].includes(state.currentSection)) {
       navigate('catalog');
     }
   }
 }
 
 function formatPrice(amount) {
   return new Intl.NumberFormat('es-ES', { style: 'currency', currency: 'EUR' }).format(amount);
 }
 
 // ══════════════════════════════════════════════════════
 //  CATÁLOGO DE PRODUCTOS
 // ══════════════════════════════════════════════════════
 
 const categoryEmoji = {
   casco: '🪖',
   ropa: '👕',
   modelo: '🏎️',
   accesorios: '🔧',
   coleccionable: '🏆',
 };
 
 function productEmoji(category) {
   return categoryEmoji[category] || '📦';
 }
 
 async function loadProducts() {
   // Mostrar spinner de carga
   document.getElementById('productsGrid').innerHTML =
     '<div class="loading-state" id="loadingState">' +
     '<div class="spinner"></div><span>Cargando productos...</span></div>';
   document.getElementById('emptyState').classList.add('hidden');
 
   const search   = encodeURIComponent(document.getElementById('searchInput').value.trim());
   const category = encodeURIComponent(document.getElementById('filterCategory').value);
   const sort     = encodeURIComponent(document.getElementById('filterSort').value);
 
   const params = new URLSearchParams();
   if (search)   params.set('search',   search);
   if (category) params.set('category', category);
   if (sort)     params.set('sort',     sort);
 
   const { ok, status, data } = await apiFetch(`/products?${params.toString()}`);
 
   if (!ok) {
     // Mostrar error claro en vez de quedarse colgado
     const msg = data.message || 'Error al conectar con el servidor.';
     const isOffline = status === 0;
     document.getElementById('productsGrid').innerHTML =
       `<div class="loading-state" style="color:#ff6666">
         <div style="font-size:2.5rem">${isOffline ? '🔌' : '⚠️'}</div>
         <strong style="font-size:1rem">${isOffline ? 'Backend no disponible' : 'Error del servidor'}</strong>
         <span style="font-size:0.85rem;max-width:380px;text-align:center">${escapeHtml(msg)}</span>
         ${isOffline ? '<span style="font-size:0.78rem;color:#888">Ejecuta: <code>docker-compose up --build</code></span>' : ''}
         <button class="btn-outline" onclick="loadProducts()" style="margin-top:8px">🔄 Reintentar</button>
       </div>`;
     return;
   }
 
   state.products = data.products || [];
   renderProducts(state.products);
 }
 
 function renderProducts(products) {
   const grid = document.getElementById('productsGrid');
   const empty = document.getElementById('emptyState');
 
   if (!products.length) {
     grid.innerHTML = '';
     empty.classList.remove('hidden');
     return;
   }
 
   empty.classList.add('hidden');
   // Construir con textContent / createElement para evitar XSS
   grid.innerHTML = products.map(p => buildProductCard(p)).join('');
 
   // Agregar event listeners a las tarjetas
   grid.querySelectorAll('.product-card').forEach(card => {
     card.addEventListener('click', (e) => {
       if (e.target.closest('.btn-add-cart')) return; // no abrir modal al clicar en Add Cart
       const id = card.dataset.productId;
       const product = state.products.find(p => String(p.id) === String(id));
       if (product) openProductModal(product);
     });
   });
 
   grid.querySelectorAll('.btn-add-cart').forEach(btn => {
     btn.addEventListener('click', (e) => {
       e.stopPropagation();
       const id = btn.dataset.productId;
       const product = state.products.find(p => String(p.id) === String(id));
       if (product) addToCart(product);
     });
   });
 }
 
 function buildProductCard(p) {
   const isOwn = state.currentUser && String(p.seller_id) === String(state.currentUser.id);
   const imgTag = safeUrl(p.image_url)
     ? `<img src="${escapeHtml(safeUrl(p.image_url))}" alt="${escapeHtml(p.name)}" loading="lazy" onerror="this.parentElement.innerHTML='${productEmoji(p.category)}'">`
     : productEmoji(p.category);
 
   return `
     <div class="product-card${isOwn ? ' own-product' : ''}" data-product-id="${escapeHtml(String(p.id))}">
       <div class="product-card-img">${imgTag}</div>
       ${isOwn ? '<span class="product-card-badge">Tuyo</span>' : ''}
       <div class="product-card-body">
         <div class="product-card-category">${escapeHtml(p.category || 'Sin categoría')}</div>
         <div class="product-card-name">${escapeHtml(p.name)}</div>
         <div class="product-card-desc">${escapeHtml(p.description)}</div>
         <div class="product-card-footer">
           <div>
             <div class="product-card-price">${formatPrice(p.price)}</div>
             <div class="product-card-seller">por @${escapeHtml(p.seller_username || 'Vendedor')}</div>
           </div>
           ${!isOwn ? `<button class="btn-add-cart" data-product-id="${escapeHtml(String(p.id))}">Añadir</button>` : ''}
         </div>
       </div>
     </div>`;
 }
 
 // ── FILTROS (debounce para no spamear la API) ──
 
 let searchDebounce;
 document.getElementById('searchInput').addEventListener('input', () => {
   clearTimeout(searchDebounce);
   searchDebounce = setTimeout(loadProducts, 400);
 });
 document.getElementById('filterCategory').addEventListener('change', loadProducts);
 document.getElementById('filterSort').addEventListener('change', loadProducts);
 
 // ── MODAL DE DETALLE DE PRODUCTO ──
 
 function openProductModal(product) {
   const content = document.getElementById('modalProductContent');
   const imgTag = safeUrl(product.image_url)
     ? `<img src="${escapeHtml(safeUrl(product.image_url))}" alt="${escapeHtml(product.name)}" onerror="this.parentElement.innerHTML='${productEmoji(product.category)}'">`
     : `<span style="font-size:5rem">${productEmoji(product.category)}</span>`;
 
   const isOwn = state.currentUser && String(product.seller_id) === String(state.currentUser.id);
 
   content.innerHTML = `
     <div class="product-detail">
       <div class="product-detail-img">${imgTag}</div>
       <div class="product-detail-info">
         <div class="product-detail-category">${escapeHtml(product.category)}</div>
         <div class="product-detail-name">${escapeHtml(product.name)}</div>
         <div class="product-detail-price">${formatPrice(product.price)}</div>
         <div class="product-detail-desc">${escapeHtml(product.description)}</div>
         <div class="product-detail-seller">Vendido por <strong>@${escapeHtml(product.seller_username)}</strong></div>
         ${!isOwn ? `<button class="btn-primary full-width" id="modalAddCart">Añadir al Carrito</button>` : `<div class="product-card-badge" style="display:inline-block">Tu producto</div>`}
       </div>
     </div>`;
 
   if (!isOwn) {
     document.getElementById('modalAddCart').addEventListener('click', () => {
       addToCart(product);
       closeModal('modalProduct');
     });
   }
 
   openModal('modalProduct');
 }
 
 // ══════════════════════════════════════════════════════
 //  CARRITO
 // ══════════════════════════════════════════════════════
 
 function addToCart(product) {
   if (!state.currentUser) {
     showToast('Inicia sesión para añadir al carrito.', 'error');
     openModal('modalLogin');
     return;
   }
 
   // Evitar añadir el propio producto
   if (String(product.seller_id) === String(state.currentUser.id)) {
     showToast('No puedes comprar tus propios productos.', 'error');
     return;
   }
 
   const existing = state.cart.find(item => item.product.id === product.id);
   if (existing) {
     existing.quantity += 1;
   } else {
     state.cart.push({ product, quantity: 1 });
   }
 
   updateCartBadge();
   showToast(`${product.name} añadido al carrito 🛒`, 'success');
 }
 
 function removeFromCart(productId) {
   state.cart = state.cart.filter(item => item.product.id !== productId);
   updateCartBadge();
   renderCartItems();
 }
 
 function changeCartQty(productId, delta) {
   const item = state.cart.find(i => i.product.id === productId);
   if (!item) return;
   item.quantity += delta;
   if (item.quantity <= 0) {
     removeFromCart(productId);
     return;
   }
   renderCartItems();
   updateCartBadge();
 }
 
 function updateCartBadge() {
   const total = state.cart.reduce((sum, i) => sum + i.quantity, 0);
   document.getElementById('cartBadge').textContent = total;
 }
 
 function renderCartItems() {
   const container = document.getElementById('cartItems');
   const footer = document.getElementById('cartFooter');
 
   if (!state.cart.length) {
     container.innerHTML = `<div class="empty-state"><div class="empty-icon">🏎️</div><p>Tu carrito está vacío</p></div>`;
     footer.classList.add('hidden');
     return;
   }
 
   footer.classList.remove('hidden');
 
   container.innerHTML = state.cart.map(item => {
     const imgTag = safeUrl(item.product.image_url)
       ? `<img src="${escapeHtml(safeUrl(item.product.image_url))}" alt="${escapeHtml(item.product.name)}" onerror="this.style.display='none'">`
       : productEmoji(item.product.category);
 
     return `
       <div class="cart-item">
         <div class="cart-item-thumb">${imgTag}</div>
         <div class="cart-item-info">
           <div class="cart-item-name">${escapeHtml(item.product.name)}</div>
           <div class="cart-item-price">${formatPrice(item.product.price)} × ${item.quantity}</div>
         </div>
         <div class="cart-item-qty">
           <button class="btn-qty" data-action="minus" data-id="${escapeHtml(String(item.product.id))}">−</button>
           <span class="cart-item-qty-num">${item.quantity}</span>
           <button class="btn-qty" data-action="plus" data-id="${escapeHtml(String(item.product.id))}">+</button>
         </div>
       </div>`;
   }).join('');
 
   // Event listeners qty buttons
   container.querySelectorAll('.btn-qty').forEach(btn => {
     btn.addEventListener('click', () => {
       const id = parseInt(btn.dataset.id, 10);
       const delta = btn.dataset.action === 'plus' ? 1 : -1;
       changeCartQty(id, delta);
     });
   });
 
   // Total
   const total = state.cart.reduce((sum, i) => sum + (i.product.price * i.quantity), 0);
   document.getElementById('cartTotalPrice').textContent = formatPrice(total);
 }
 
 // Cart toggle
 document.getElementById('btnCart').addEventListener('click', () => {
   const sidebar = document.getElementById('cartSidebar');
   const overlay = document.getElementById('cartOverlay');
   renderCartItems();
   sidebar.classList.remove('hidden');
   sidebar.classList.add('open');
   overlay.classList.remove('hidden');
 });
 
 document.getElementById('btnCloseCart').addEventListener('click', closeCart);
 document.getElementById('cartOverlay').addEventListener('click', closeCart);
 
 function closeCart() {
   document.getElementById('cartSidebar').classList.remove('open');
   document.getElementById('cartOverlay').classList.add('hidden');
   setTimeout(() => document.getElementById('cartSidebar').classList.add('hidden'), 300);
 }
 
 // ── CHECKOUT ──
 
 document.getElementById('btnCheckout').addEventListener('click', async () => {
   if (!state.currentUser) {
     showToast('Debes iniciar sesión para comprar.', 'error');
     return;
   }
   if (!state.cart.length) {
     showToast('El carrito está vacío.', 'error');
     return;
   }
 
   const total = state.cart.reduce((sum, i) => sum + (i.product.price * i.quantity), 0);
   const confirmed = await showConfirm(
     'Confirmar compra',
     `Total a pagar: ${formatPrice(total)}. ¿Confirmas la compra?`
   );
   if (!confirmed) return;
 
   const items = state.cart.map(i => ({ product_id: i.product.id, quantity: i.quantity }));
 
   const { ok, data } = await apiFetch('/orders', {
     method: 'POST',
     body: JSON.stringify({ items }),
   });
 
   if (!ok) {
     showToast(data.message || 'Error al procesar la compra.', 'error');
     return;
   }
 
   // Actualizar balance del usuario
   if (data.new_balance !== undefined) {
     state.currentUser.balance = data.new_balance;
     updateAuthUI();
   }
 
   state.cart = [];
   updateCartBadge();
   closeCart();
   showToast('¡Compra realizada con éxito! 🏆', 'success');
 });
 
 // ══════════════════════════════════════════════════════
 //  VENDER PRODUCTO
 // ══════════════════════════════════════════════════════
 
 // Contador de caracteres en descripción
 document.getElementById('prodDesc').addEventListener('input', function() {
   document.getElementById('charCount').textContent = `${this.value.length}/500`;
 });
 
 document.getElementById('sellForm').addEventListener('submit', async (e) => {
   e.preventDefault();
 
   const name = document.getElementById('prodName').value.trim();
   const category = document.getElementById('prodCategory').value;
   const desc = document.getElementById('prodDesc').value.trim();
   const price = document.getElementById('prodPrice').value;
   const imageUrl = document.getElementById('prodImageUrl').value.trim();
 
   // Limpiar errores previos
   ['errProdName','errProdCategory','errProdDesc','errProdPrice','errProdImageUrl']
     .forEach(id => setFieldError(id, ''));
 
   let hasError = false;
 
   const nameErr = validators.productName(name);
   if (nameErr) { setFieldError('errProdName', nameErr); hasError = true; }
 
   if (!category) { setFieldError('errProdCategory', 'Selecciona una categoría.'); hasError = true; }
 
   const descErr = validators.productDesc(desc);
   if (descErr) { setFieldError('errProdDesc', descErr); hasError = true; }
 
   const priceErr = validators.productPrice(price);
   if (priceErr) { setFieldError('errProdPrice', priceErr); hasError = true; }
 
   if (imageUrl && !safeUrl(imageUrl)) {
     setFieldError('errProdImageUrl', 'La URL debe comenzar con https://');
     hasError = true;
   }
 
   if (hasError) return;
 
   const btn = document.getElementById('btnSellSubmit');
   toggleBtnLoading(btn, true);
 
   const body = {
     name,
     category,
     description: desc,
     price: parseFloat(price),
   };
   if (safeUrl(imageUrl)) body.image_url = safeUrl(imageUrl);
 
   const { ok, data } = await apiFetch('/products', {
     method: 'POST',
     body: JSON.stringify(body),
   });
 
   toggleBtnLoading(btn, false);
 
   if (!ok) {
     showToast(data.message || 'Error al publicar el producto.', 'error');
     return;
   }
 
   document.getElementById('sellForm').reset();
   document.getElementById('charCount').textContent = '0/500';
   showToast('¡Producto publicado con éxito! 🏁', 'success');
   navigate('catalog');
 });
 
 // ══════════════════════════════════════════════════════
 //  MIS COMPRAS
 // ══════════════════════════════════════════════════════
 
 async function loadMyOrders() {
   const container = document.getElementById('myOrdersList');
   container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Cargando...</span></div>`;
 
   const { ok, data } = await apiFetch('/orders/my');
 
   if (!ok) {
     container.innerHTML = '';
     showToast(data.message || 'Error al cargar las compras.', 'error');
     return;
   }
 
   const orders = data.orders || [];
 
   if (!orders.length) {
     container.innerHTML = `
       <div class="empty-state">
         <div class="empty-icon">🛒</div>
         <p>Aún no has realizado ninguna compra</p>
         <button class="btn-outline" onclick="navigate('catalog')">Ver Catálogo</button>
       </div>`;
     return;
   }
 
   container.innerHTML = orders.map(order => {
     const imgTag = safeUrl(order.product_image)
       ? `<img src="${escapeHtml(safeUrl(order.product_image))}" alt="${escapeHtml(order.product_name)}" onerror="this.style.display='none'">`
       : productEmoji(order.product_category);
 
     return `
       <div class="order-card">
         <div class="order-thumb">${imgTag}</div>
         <div class="order-info">
           <div class="order-name">${escapeHtml(order.product_name)}</div>
           <div class="order-meta">Cantidad: ${escapeHtml(String(order.quantity))} · ${new Date(order.created_at).toLocaleDateString('es-ES')}</div>
         </div>
         <div>
           <div class="order-price">${formatPrice(order.total_price)}</div>
           <div class="order-status">Completado</div>
         </div>
       </div>`;
   }).join('');
 }
 
 // ══════════════════════════════════════════════════════
 //  MIS PRODUCTOS
 // ══════════════════════════════════════════════════════
 
 async function loadMyProducts() {
   const container = document.getElementById('myProductsList');
   container.innerHTML = `<div class="loading-state"><div class="spinner"></div><span>Cargando...</span></div>`;
 
   const { ok, data } = await apiFetch('/products/my');
 
   if (!ok) {
     container.innerHTML = '';
     showToast(data.message || 'Error al cargar los productos.', 'error');
     return;
   }
 
   const products = data.products || [];
 
   if (!products.length) {
     container.innerHTML = `
       <div class="empty-state" style="grid-column:1/-1">
         <div class="empty-icon">📦</div>
         <p>Aún no has publicado ningún producto</p>
         <button class="btn-outline" onclick="navigate('sell')">Publicar Producto</button>
       </div>`;
     return;
   }
 
   container.innerHTML = products.map(p => `
     <div class="product-card own-product" data-product-id="${escapeHtml(String(p.id))}">
       <div class="product-card-img">${safeUrl(p.image_url) ? `<img src="${escapeHtml(safeUrl(p.image_url))}" alt="${escapeHtml(p.name)}" loading="lazy">` : productEmoji(p.category)}</div>
       <span class="product-card-badge">Tuyo</span>
       <div class="product-card-body">
         <div class="product-card-category">${escapeHtml(p.category)}</div>
         <div class="product-card-name">${escapeHtml(p.name)}</div>
         <div class="product-card-desc">${escapeHtml(p.description)}</div>
         <div class="product-card-price">${formatPrice(p.price)}</div>
         <div class="product-actions">
           <button class="btn-edit" data-id="${escapeHtml(String(p.id))}">Editar</button>
           <button class="btn-delete" data-id="${escapeHtml(String(p.id))}">Eliminar</button>
         </div>
       </div>
     </div>`).join('');
 
   // Delete
   container.querySelectorAll('.btn-delete').forEach(btn => {
     btn.addEventListener('click', async () => {
       const confirmed = await showConfirm('Eliminar producto', '¿Seguro que quieres eliminar este producto? Esta acción no se puede deshacer.');
       if (!confirmed) return;
       await deleteProduct(btn.dataset.id);
     });
   });
 
   // Edit (simple: rellena formulario de venta)
   container.querySelectorAll('.btn-edit').forEach(btn => {
     btn.addEventListener('click', () => {
       const product = products.find(p => String(p.id) === String(btn.dataset.id));
       if (product) prefillEditForm(product);
     });
   });
 }
 
 async function deleteProduct(productId) {
   const { ok, data } = await apiFetch(`/products/${encodeURIComponent(productId)}`, { method: 'DELETE' });
 
   if (!ok) {
     showToast(data.message || 'Error al eliminar el producto.', 'error');
     return;
   }
   showToast('Producto eliminado.', 'success');
   loadMyProducts();
 }
 
 function prefillEditForm(product) {
   navigate('sell');
   document.getElementById('prodName').value = product.name;
   document.getElementById('prodCategory').value = product.category;
   document.getElementById('prodDesc').value = product.description;
   document.getElementById('charCount').textContent = `${product.description.length}/500`;
   document.getElementById('prodPrice').value = product.price;
   if (product.image_url) document.getElementById('prodImageUrl').value = product.image_url;
 
   // Cambiar el botón para que haga PUT
   const btn = document.getElementById('btnSellSubmit');
   btn.querySelector('span').textContent = 'Guardar Cambios';
   btn.dataset.editId = product.id;
 }
 
 // Override del submit para edición
 document.getElementById('sellForm').addEventListener('submit', async (e) => {
   const btn = document.getElementById('btnSellSubmit');
   if (!btn.dataset.editId) return; // manejo normal de creación ya en el listener de arriba
   e.stopImmediatePropagation();
   e.preventDefault();
 
   const name = document.getElementById('prodName').value.trim();
   const category = document.getElementById('prodCategory').value;
   const desc = document.getElementById('prodDesc').value.trim();
   const price = document.getElementById('prodPrice').value;
   const imageUrl = document.getElementById('prodImageUrl').value.trim();
 
   let hasError = false;
   ['errProdName','errProdCategory','errProdDesc','errProdPrice'].forEach(id => setFieldError(id, ''));
 
   if (validators.productName(name)) { setFieldError('errProdName', validators.productName(name)); hasError = true; }
   if (!category) { setFieldError('errProdCategory', 'Selecciona categoría.'); hasError = true; }
   if (validators.productDesc(desc)) { setFieldError('errProdDesc', validators.productDesc(desc)); hasError = true; }
   if (validators.productPrice(price)) { setFieldError('errProdPrice', validators.productPrice(price)); hasError = true; }
   if (hasError) return;
 
   toggleBtnLoading(btn, true);
 
   const body = { name, category, description: desc, price: parseFloat(price) };
   if (safeUrl(imageUrl)) body.image_url = safeUrl(imageUrl);
 
   const editId = encodeURIComponent(btn.dataset.editId);
   const { ok, data } = await apiFetch(`/products/${editId}`, {
     method: 'PUT',
     body: JSON.stringify(body),
   });
 
   toggleBtnLoading(btn, false);
 
   if (!ok) { showToast(data.message || 'Error al actualizar.', 'error'); return; }
 
   delete btn.dataset.editId;
   btn.querySelector('span').textContent = 'Publicar Producto';
   document.getElementById('sellForm').reset();
   document.getElementById('charCount').textContent = '0/500';
   showToast('Producto actualizado con éxito ✔️', 'success');
   navigate('my-products');
 }, true); // capture = true para que se ejecute antes del otro listener
 
 // ══════════════════════════════════════════════════════
 //  HELPERS UI
 // ══════════════════════════════════════════════════════
 
 function toggleBtnLoading(btn, loading) {
   const span = btn.querySelector('span');
   const loader = btn.querySelector('.btn-loader');
   if (!span || !loader) return;
   btn.disabled = loading;
   span.style.display = loading ? 'none' : '';
   loader.classList.toggle('hidden', !loading);
 }
 
 // Toggle mostrar/ocultar contraseña
 document.querySelectorAll('.btn-toggle-pw').forEach(btn => {
   btn.addEventListener('click', () => {
     const input = document.getElementById(btn.dataset.target);
     if (!input) return;
     input.type = input.type === 'password' ? 'text' : 'password';
     btn.textContent = input.type === 'password' ? '👁' : '🙈';
   });
 });
 
 // ══════════════════════════════════════════════════════
 //  INICIALIZACIÓN
 // ══════════════════════════════════════════════════════
 
 function init() {
   // Cargar productos al arrancar
   loadProducts();
   // Ocultar secciones privadas del nav si no hay sesión
   updateAuthUI();
 }
 
 document.addEventListener('DOMContentLoaded', init);