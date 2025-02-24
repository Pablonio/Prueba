
# WebWar - Auditoría Web Avanzada

WebWar es una herramienta de auditoría de vulnerabilidades en aplicaciones web, desarrollada en Python. Permite realizar escaneos avanzados de puertos, análisis SSL/TLS, pruebas de inyección (SQLi, XSS, SSTI, LFI, inyección de comandos), fuerza bruta de directorios y enumeración de subdominios, entre otras funcionalidades. Además, si no se encuentran las wordlists necesarias en el sistema, el script las descarga automáticamente.

## Características

- **Escaneo de puertos avanzado:** Utiliza Nmap para detectar servicios y vulnerabilidades conocidas.
- **Análisis SSL/TLS:** Verifica certificados y protocolos inseguros.
- **Pruebas de vulnerabilidades web:** Incluye pruebas para inyección SQL, XSS, inyección de comandos, SSTI y LFI.
- **Fuerza bruta de directorios y subdominios:** Emplea wordlists descargables automáticamente si no se encuentran en el sistema.
- **Interfaz interactiva:** Solicita de forma interactiva los parámetros del escaneo, como el target, nombre del archivo de salida, modo agresivo y número de hilos.
- **Compatibilidad multiplataforma:** Funciona tanto en Linux como en Windows, ajustando automáticamente la ubicación de las wordlists.

## Requisitos

- **Python 3.x:** Se recomienda instalar la última versión de Python 3.
- **Dependencias de Python:**  
  Instala las siguientes librerías usando `pip`:
  - `requests`
  - `python-nmap`
  - `dnspython`
  - `beautifulsoup4`
- **Nmap:**  
  La herramienta Nmap debe estar instalada en el sistema.
  - En Linux: `sudo apt-get install nmap`
  - En Windows: Descárgala e instálala desde [nmap.org](https://nmap.org/).

## Instalación

1. **Clonar el repositorio:**

   ```bash
   git clone https://github.com/tu_usuario/webwar.git
   cd webwar
   ```

2. **Crear un entorno virtual (opcional pero recomendado):**

   ```bash
   python3 -m venv venv
   source venv/bin/activate   # En Linux/Mac
   venv\Scripts\activate      # En Windows
   ```

3. **Instalar las dependencias:**

   Si el repositorio incluye un archivo `requirements.txt`, ejecuta:

   ```bash
   pip install -r requirements.txt
   ```

   Si no, instala manualmente:

   ```bash
   pip install requests python-nmap dnspython beautifulsoup4
   ```

## Uso

1. **Ejecutar la herramienta:**

   ```bash
   python3 webwar.py
   ```

2. **Ingresar los parámetros cuando se soliciten:**

   - **Target:** Dominio o IP que se desea auditar.
   - **Nombre del archivo de salida:** Donde se guardará el reporte del escaneo.
   - **Modo agresivo:** Indica si se desea realizar un escaneo más profundo (responde `s` para sí o `n` para no).
   - **Número de hilos:** Define cuántos hilos se usarán para tareas concurrentes (por defecto 50).

3. **Descarga automática de wordlists:**

   Si no se encuentra el directorio de wordlists en la ruta configurada (por defecto `/usr/share/seclists` en Linux o una carpeta `seclists` en el directorio actual para Windows), el script:
   - Creará el directorio `seclists` en el directorio actual.
   - Descargará automáticamente los archivos esenciales:
     - `common.txt` para fuerza bruta de directorios.
     - `subdomains-top1million-110000.txt` para enumeración de subdominios.
   - Se mostrará la ruta donde se han descargado las wordlists.

## Notas adicionales

- **Permisos:** Ejecuta la herramienta con los permisos adecuados. Algunas funciones pueden requerir privilegios elevados.
- **Uso Responsable:** Esta herramienta debe usarse únicamente en entornos y sistemas autorizados para pruebas de seguridad. El uso no autorizado puede tener implicaciones legales.
- **Modificaciones:** Puedes ampliar o ajustar las pruebas de vulnerabilidad y los payloads según tus necesidades.

## Contribución

Si deseas contribuir al desarrollo o mejora de WebWar, por favor abre un issue o envía un Pull Request en el repositorio.

## Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

## Contacto

Si tienes dudas o sugerencias, abre un [issue](https://github.com/tu_usuario/webwar/issues) en GitHub o contáctame a través de mi perfil.

---

¡Utiliza WebWar de forma responsable y feliz auditoría!
```
