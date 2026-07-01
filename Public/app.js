// MANEJO DEL REGISTRO DE USUARIOS 
document.getElementById('signup-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const fullName = document.getElementById('signup-name').value.trim();
    const email = document.getElementById('signup-email').value.trim();
    const password = document.getElementById('signup-password').value;
    const resultElement = document.getElementById('signup-result');

    if (fullName.length < 5) {
        resultElement.className = "error";
        resultElement.innerText = "Error: El nombre completo debe tener al menos 5 caracteres.";
        return;
    }

    const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(password)) {
        resultElement.className = "error";
        resultElement.innerText = "Error: La contraseña debe tener al menos 8 caracteres, con al menos un número y una letra.";
        return;
    }

    resultElement.className = "";
    resultElement.innerText = "Enviando datos al servidor...";

    try {
        const res = await fetch('/api/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ full_name: fullName, email, password })
        });

        const data = await res.json();

        if (res.ok) {
            resultElement.className = "success";
            resultElement.innerText = data.message;
            document.getElementById('signup-form').reset();
        } else {
            resultElement.className = "error";
            resultElement.innerText = data.error;
        }
    } catch (error) {
        resultElement.className = "error";
        resultElement.innerText = "Error al conectar con el servidor.";
    }
});

// MANEJO DEL INICIO DE SESIÓN 
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const resultElement = document.getElementById('login-result');

    resultElement.className = "";
    resultElement.innerText = "Comprobando credenciales...";

    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();

        if (res.ok) {
            localStorage.setItem('sessionToken', data.sessionToken);
            document.getElementById('user-name').innerText = data.fullName;

            document.getElementById('signup-container').classList.add('hidden');
            document.getElementById('login-container').classList.add('hidden');
            document.getElementById('welcome-view').classList.remove('hidden');

            startInactivityCheck();
        } else {
            resultElement.className = "error";
            resultElement.innerText = data.error; 
        }
    } catch (error) {
        resultElement.className = "error";
        resultElement.innerText = "Error al conectar con el servidor.";
    }
});

// MANEJO DEL CIERRE DE SESIÓN (LOGOUT)
document.getElementById('logout-link').addEventListener('click', async (e) => {
    e.preventDefault();
    await executeLogout();
});

async function executeLogout() {
    const token = localStorage.getItem('sessionToken');
    try {
        await fetch('/api/logout', {
            method: 'POST',
            headers: { 'token': token }
        });
    } catch (error) {
        console.error("Error al cerrar sesión:", error);
    }
    localStorage.removeItem('sessionToken');
    window.location.reload();
}

// MONITOREO DE INACTIVIDAD OPTIMIZADO 
let inactivityIntervalId = null;

function startInactivityCheck() {
    if (inactivityIntervalId) clearInterval(inactivityIntervalId);

    async function checkJob() {
        const token = localStorage.getItem('sessionToken');
        if (!token) return;

        try {
            const res = await fetch('/api/verify-session', {
                method: 'GET',
                headers: { 'token': token }
            });

            if (res.status === 401) {
                clearInterval(inactivityIntervalId);
                const data = await res.json();
                alert(data.error || "Su sesión ha expirado por inactividad.");
                localStorage.removeItem('sessionToken');
                window.location.reload();
            }
        } catch (error) {
            console.error("Error en la petición de monitoreo:", error);
        }
    }

    // aqui informamos al servidor que hubo interacción real de forma inmediata
    const notifyActivity = () => {
        const token = localStorage.getItem('sessionToken');
        if (!token) return;
        fetch('/api/update-activity', { method: 'POST', headers: { 'token': token } }).catch(() => {});
    };

    // detectar interacciones
    document.addEventListener('mousedown', notifyActivity);
    document.addEventListener('keydown', notifyActivity);

    // Revisar el estado en la terminal cada 5 segundos continuos
    inactivityIntervalId = setInterval(checkJob, 5 * 1000);
}

window.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('sessionToken');
    if (token) {
        startInactivityCheck();
    }
});