import os
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Crear una carpeta para los recursos si no existe
def create_folder(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

# Descargar los recursos (imágenes, CSS, JS)
def download_resource(session, url, folder, relative_path):
    try:
        url_clean = clean_url(url)  # Limpiar URL
        resource_response = session.get(url_clean)
        if resource_response.status_code == 200:
            # Mantener la estructura de carpetas original
            full_folder = os.path.join(folder, os.path.dirname(relative_path))
            create_folder(full_folder)

            filename = os.path.join(full_folder, os.path.basename(url_clean))
            with open(filename, 'wb') as file:
                file.write(resource_response.content)
            print(f"Recurso descargado: {filename}")
            return os.path.join(os.path.dirname(relative_path), os.path.basename(url_clean))
        else:
            print(f"No se pudo descargar {url_clean}, estado: {resource_response.status_code}")
            return None
    except Exception as e:
        print(f"Error al descargar {url_clean}: {e}")
        return None

# Limpiar la URL y eliminar los parámetros para generar nombres de archivos válidos
def clean_url(url):
    return url.split('?')[0]

# Descargar y procesar archivos CSS para encontrar y descargar recursos embebidos
def process_css(session, css_url, folder, relative_path):
    local_css_path = download_resource(session, css_url, folder, relative_path)
    if local_css_path:
        full_css_path = os.path.join(folder, local_css_path)
        with open(full_css_path, 'r', encoding='utf-8') as css_file:
            css_content = css_file.read()

        # Buscar todas las URL en el CSS (ej. imágenes de fondo, fuentes, etc.)
        urls = re.findall(r'url\((.*?)\)', css_content)
        for url in urls:
            url = url.strip('\'"')
            if not url.startswith('http'):
                url = urljoin(css_url, url)
            resource_folder = 'clon/' + ('images' if url.endswith(('.png', '.jpg', '.jpeg', '.gif')) else 'fonts')
            relative_resource = os.path.join(os.path.dirname(relative_path), os.path.basename(url))
            local_resource = download_resource(session, url, resource_folder, relative_resource)
            if local_resource:
                css_content = css_content.replace(url, os.path.join('..', local_resource))

        # Guardar el CSS actualizado
        with open(full_css_path, 'w', encoding='utf-8') as css_file:
            css_file.write(css_content)

# Clonar la página web y descargar todos los recursos
def clone_website(url, username=None, password=None):
    session = requests.Session()

    # Si se proporcionan credenciales, iniciar sesión
    if username and password:
        login_url = 'https://auth.bncr.fi.cr/adfs/ls/'  # URL de inicio de sesión
        login_data = {
            'username': username,
            'password': password,
            'other_required_field': 'value'  # Si hay otros campos necesarios
        }
        
        # Imprimir las credenciales ingresadas en pantalla
        print(f"Iniciando sesión con usuario: {username} y contraseña: {password}")
        
        login_response = session.post(login_url, data=login_data)

        if login_response.status_code != 200:
            print("Error al iniciar sesión, verifica tus credenciales.")
            return

    response = session.get(url)
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Crear carpetas para los recursos
        create_folder('clon')
        create_folder('clon/images')
        create_folder('clon/css')
        create_folder('clon/js')
        create_folder('clon/fonts')

        # Descargar y reemplazar las imágenes
        for img in soup.find_all('img'):
            img_url = img['src']
            if img_url.startswith('data:image'):  # Ignorar imágenes embebidas en base64
                print(f"Recurso embebido en base64, no requiere descarga: {img_url[:30]}...")
                continue
            else:
                img_url = urljoin(base_url, img_url)

                # Cambiar la ruta si contiene 'adfs'
                if 'adfs' in img_url and img_url.endswith(('.png', '.jpg')):
                    img_relative_path = '/clon/images/css/' + os.path.basename(img_url)
                    img['src'] = img_relative_path
                    print(f"Ruta de imagen modificada a: {img_relative_path}")
                else:
                    img_relative_path = os.path.join('images', os.path.basename(img_url))
                    local_img_path = download_resource(session, img_url, 'clon', img_relative_path)
                    if local_img_path:
                        img['src'] = os.path.join(local_img_path)

        # Descargar y procesar los archivos CSS
        for link in soup.find_all('link', {'rel': 'stylesheet'}):
            css_url = urljoin(base_url, link['href'])
            css_relative_path = os.path.join('css', os.path.basename(css_url))
            process_css(session, css_url, 'clon', css_relative_path)
            link['href'] = os.path.join(css_relative_path)

        # Descargar y reemplazar los archivos JS
        for script in soup.find_all('script', {'src': True}):
            js_url = urljoin(base_url, script['src'])
            js_relative_path = os.path.join('js', os.path.basename(js_url))
            local_js_path = download_resource(session, js_url, 'clon', js_relative_path)
            if local_js_path:
                script['src'] = os.path.join(js_relative_path)

        # Guardar la página HTML con los recursos locales
        with open('clon/index.html', 'w', encoding='utf-8') as file:
            file.write(soup.prettify())
        print(f"Página clonada guardada en 'clon/index.html'")
    else:
        print(f"No se pudo acceder a la página. Código de estado: {response.status_code}")

# Ejemplo de uso con autenticación
clone_website(input ("ingrese la url a clonar: "),
    username='tu_usuario',
    password='tu_contraseña'
)