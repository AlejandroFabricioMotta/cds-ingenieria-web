(function () {
  'use strict';
  var datos = JSON.parse(document.getElementById('rs-datos').textContent);
  var puerta = document.getElementById('rsPuerta'), form = document.getElementById('rsForm'),
      campo = document.getElementById('rsClave'), error = document.getElementById('rsError'),
      destino = document.getElementById('rsContenido'), menuNav = document.getElementById('menuNav'),
      menuBoton = document.getElementById('menuBoton'), enlacesInternos = document.getElementById('rsEnlaces');
  var b64 = function (s) { var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; };
  var te = new TextEncoder(), td = new TextDecoder();

  menuBoton.addEventListener('click', function () {
    var ab = menuNav.classList.toggle('abierto'); menuBoton.setAttribute('aria-expanded', ab ? 'true' : 'false');
  });
  menuNav.addEventListener('click', function (e) { if (e.target.tagName === 'A') { menuNav.classList.remove('abierto'); menuBoton.setAttribute('aria-expanded', 'false'); } });

  function derivar(clave) {
    return crypto.subtle.importKey('raw', te.encode(clave), 'PBKDF2', false, ['deriveKey']).then(function (km) {
      return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(datos.salt), iterations: datos.it, hash: 'SHA-256' },
        km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    });
  }
  function descifrar(k, buf) {
    var u = new Uint8Array(buf);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, k, u.slice(12));
  }
  function cargarArchivos(k) {
    var nodos = Array.prototype.slice.call(destino.querySelectorAll('[data-enc]'));
    var cola = nodos.slice(), activos = 0, max = 6;
    function siguiente() {
      while (activos < max && cola.length) {
        (function (n) {
          activos++;
          var info = datos.archivos[n.getAttribute('data-enc')];
          fetch(info.f).then(function (r) { if (!r.ok) throw new Error(r.status); return r.arrayBuffer(); })
            .then(function (b) { return descifrar(k, b); })
            .then(function (p) {
              var url = URL.createObjectURL(new Blob([p], { type: info.m }));
              if (n.tagName === 'IMG') { n.src = url; } else { n.href = url; }
            })
            .catch(function () { if (n.tagName === 'IMG') n.alt = (n.alt || '') + ' (no se pudo cargar)'; })
            .then(function () { activos--; siguiente(); });
        })(cola.shift());
      }
    }
    siguiente();
  }
  function abrir(clave, recordar) {
    return derivar(clave).then(function (k) {
      return descifrar(k, b64(datos.html).buffer).then(function (p) {
        destino.innerHTML = td.decode(p);
        puerta.classList.add('rs-oculto'); destino.classList.remove('rs-oculto'); enlacesInternos.classList.remove('rs-oculto');
        document.title = datos.titulo;
        if (recordar) { try { sessionStorage.setItem('rs-clave', clave); } catch (e) {} }
        cargarArchivos(k);
        if (location.hash) { setTimeout(function () { var t = document.getElementById(location.hash.slice(1)); if (t) t.scrollIntoView(); }, 50); }
      });
    });
  }
  form.addEventListener('submit', function (e) {
    e.preventDefault(); error.textContent = '';
    var c = campo.value.trim(); if (!c) return;
    abrir(c, true).catch(function () { error.textContent = 'Clave incorrecta. Probá de nuevo.'; campo.select(); });
  });
  var guardada = null; try { guardada = sessionStorage.getItem('rs-clave'); } catch (e) {}
  if (guardada) { abrir(guardada, false).catch(function () { try { sessionStorage.removeItem('rs-clave'); } catch (e) {} }); }
  campo.focus();
})();
