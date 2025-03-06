# WebWar - Auditoría Web Avanzada

WebWar es una herramienta de auditoría de vulnerabilidades en aplicaciones web, desarrollada en Python. Permite realizar escaneos avanzados de puertos, análisis SSL/TLS, pruebas de inyección (SQLi, XSS, SSTI, LFI, inyección de comandos), fuerza bruta de directorios y enumeración de subdominios, entre otras funcionalidades. Además, si no se encuentran las wordlists necesarias en el sistema, el script las descarga automáticamente.

## Características

- **Escaneo de puertos avanzado:** Utiliza Nmap para detectar servicios y vulnerabilidades conocidas.
- **Análisis SSL/TLS:** Verifica certificados y protocolos inseguros.
- **Pruebas de vulnerabilidades web:** Incluye pruebas para inyección SQL, XSS, inyección de comandos, SSTI y LFI.
- **Fuerza bruta de directorios y subdominios:** Emplea wordlists descargables automáticamente si no se encuentran en el sistema.
- **Interfaz interactiva:** Solicita de forma interactiva los parámetros del escaneo, como el target, nombre del archivo de salida, modo agresivo y número de hilos.
- **Compatibilidad multiplataforma:** Funciona tanto en Linux como en Windows (recomendado con WSL para mejor compatibilidad con herramientas de seguridad).

## Requisitos

### Para Linux

- **Python 3.x:** Instalar la última versión.
- **Dependencias de Python:**
  ```bash
  pip install requests python-nmap dnspython beautifulsoup4
  ```
- **Nmap:**
  ```bash
  sudo apt-get install nmap
  ```

### Para Windows (usando WSL)

1. **Activar WSL (si no está habilitado):**
   ```powershell
   wsl --install
   ```
   Reinicia el sistema si es necesario.

2. **Instalar una distribución de Linux:**
   ```powershell
   wsl --install -d Ubuntu
   ```

3. **Abrir Ubuntu en WSL y actualizar paquetes:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

4. **Instalar Python y dependencias:**
   ```bash
   sudo apt install python3 python3-pip nmap
   pip3 install requests python-nmap dnspython beautifulsoup4
   ```

## Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/tu_usuario/webwar.git
   cd webwar
   ```

2. **(Opcional) Crear un entorno virtual:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # En Linux/WSL
   ```

3. **Instalar las dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

## Uso

1. **Ejecutar la herramienta:**
   ```bash
   python3 webwar.py
   ```

2. **Ingresar los parámetros cuando se soliciten:**
   - **Target:** Dominio o IP a auditar.
   - **Nombre del archivo de salida:** Donde se guardará el reporte.
   - **Modo agresivo:** Especificar si se desea un escaneo más profundo (`s` para sí, `n` para no).
   - **Número de hilos:** Definir la concurrencia (por defecto 50).

3. **Descarga automática de wordlists:**
   - Si no se encuentran las wordlists necesarias, WebWar las descargará en `seclists/` dentro del directorio actual.

## Notas adicionales

- **Permisos:** Algunas funciones requieren privilegios elevados (`sudo` en Linux/WSL).
- **Uso Responsable:** WebWar debe usarse solo en sistemas autorizados para pruebas de seguridad.
- **Modificaciones:** Se pueden personalizar las pruebas y payloads según necesidades.

## Contribución

Si deseas contribuir, abre un issue o envía un Pull Request en el repositorio.

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

## Contacto

Si tienes dudas o sugerencias, abre un [issue](https://github.com/tu_usuario/webwar/issues) en GitHub.

---

¡Utiliza WebWar de forma responsable y feliz auditoría!
Att: By Flox

