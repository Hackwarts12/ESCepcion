# ESCepcion

Plataforma segura para herramientas de seguridad.

## Características de Seguridad

- **HTTPS**: El sitio debe ser servido únicamente sobre HTTPS
- **Content Security Policy**: Implementado en el HTML para prevenir XSS
- **Validación de entrada**: Todas las entradas deben ser validadas
- **Sin secretos en el código**: Usar variables de entorno para información sensible

## Estructura del Proyecto

```
ESCepcion/
├── index.html          # Página principal
├── styles.css          # Estilos
├── app.js             # JavaScript principal
├── .gitignore         # Archivos a ignorar en Git
└── README.md          # Este archivo
```

## Deployment

### GitHub Pages (con HTTPS automático)

1. Ve a Settings > Pages en tu repositorio
2. Selecciona la rama `main` como source
3. GitHub Pages automáticamente servirá el sitio con HTTPS

### Netlify (Recomendado para mayor control)

1. Conecta tu repositorio de GitHub
2. Deploy automático con HTTPS
3. Soporte para headers de seguridad personalizados

## Configuración de Seguridad Recomendada

Para deployment en producción, asegúrate de:

1. Habilitar HTTPS (forzar redirección de HTTP a HTTPS)
2. Configurar headers de seguridad:
   - `Strict-Transport-Security`
   - `X-Content-Type-Options`
   - `X-Frame-Options`
   - `X-XSS-Protection`

## Desarrollo Local

Para probar localmente con servidor HTTPS:

```bash
# Opción 1: Python
python -m http.server 8000

# Opción 2: Node.js (http-server)
npx http-server -p 8000
```

## Próximos Pasos

- [ ] Agregar herramientas específicas
- [ ] Implementar autenticación si es necesario
- [ ] Configurar CI/CD
- [ ] Agregar tests de seguridad
