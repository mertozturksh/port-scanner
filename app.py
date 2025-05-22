from flask import Flask, render_template, request
from utils.port_scanner import PortScanner
from utils.utils import get_local_ip, get_form_data

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    if request.method == 'POST':

        form_data = get_form_data(request.form)

        source_ip = get_local_ip()
        scanner = PortScanner(
            target_ip=form_data["target_ip"],
            source_ip=source_ip,
            port_range=form_data["port_range"],
            thread_count=form_data["thread_count"],
            use_threads=True,
            socket_timeout=10,  # Her socket.recvfrom için timeout
            idle_timeout=30     # Genel tarama süresi limiti
        )

        scan_data = scanner.scan()
        error = scan_data.get('error')
        return render_template('index.html',
                             results=scan_data['results'],
                             os_guess=scan_data['os_guess'],
                             scan_time=scan_data['scan_time'],
                             error=error)
    
    return render_template('index.html', error=error)

if __name__ == '__main__':
    app.run(debug=True)
