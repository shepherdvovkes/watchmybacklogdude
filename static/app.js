// static/app.js
document.addEventListener('DOMContentLoaded', () => {

    // --- Мокап логина ---
    const loginOverlay = document.getElementById('login-overlay');
    const mainContent = document.getElementById('main-content');
    const loginForm = document.getElementById('login-form');
    const logoutButton = document.getElementById('logout-button');

    // При успешном "логине" показываем основной контент
    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        loginOverlay.style.display = 'none';
        mainContent.style.display = 'block';
        connectWebSocket();
    });
    
    // "Разлогин"
    logoutButton.addEventListener('click', () => {
        loginOverlay.style.display = 'flex';
        mainContent.style.display = 'none';
        if (window.socket) {
            window.socket.close();
        }
    });

    // --- Логика WebSocket ---
    const socketStatus = document.getElementById('socket-status');
    const logFeed = document.getElementById('log-feed');

    function connectWebSocket() {
        // Определяем протокол (ws или wss)
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/logs`;

        console.log(`Connecting to WebSocket at ${wsUrl}`);
        const socket = new WebSocket(wsUrl);
        window.socket = socket;

        socket.onopen = () => {
            console.log('WebSocket connected.');
            socketStatus.textContent = 'CONNECTED';
            socketStatus.classList.remove('bg-red-800', 'text-red-200');
            socketStatus.classList.add('bg-green-800', 'text-green-200');
        };

        socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log('Received data:', data);
            addLogEntry(data);
        };

        socket.onclose = () => {
            console.log('WebSocket disconnected.');
            socketStatus.textContent = 'DISCONNECTED';
            socketStatus.classList.remove('bg-green-800', 'text-green-200');
            socketStatus.classList.add('bg-red-800', 'text-red-200');
            // Попытка переподключения через 3 секунды
            setTimeout(connectWebSocket, 3000);
        };

        socket.onerror = (error) => {
            console.error('WebSocket error:', error);
            socket.close();
        };
    }

    // --- Рендеринг карточек ---
    function getLevelStyles(level) {
        switch (level) {
            case 'critical':
                return 'border-red-500 bg-red-900/50';
            case 'warning':
                return 'border-yellow-500 bg-yellow-900/50';
            default:
                return 'border-blue-500 bg-blue-900/50';
        }
    }

    function getSourceIcon(source) {
        if (source === 'OpenAI') return '🤖';
        if (source === 'VirusTotal') return '🦠';
        if (source === 'RAG') return '🧠';
        return '❓';
    }

    function createAnalysisHTML(analysis) {
        const levelStyles = getLevelStyles(analysis.level);
        const icon = getSourceIcon(analysis.source);

        return `
            <div class="border-l-4 ${levelStyles} p-3 rounded-r-lg">
                <p class="font-bold text-sm text-gray-300 flex items-center">${icon} ${analysis.source} Analysis</p>
                <p class="text-gray-400 text-sm">${analysis.details}</p>
            </div>
        `;
    }
    
    function addLogEntry(data) {
        const card = document.createElement('div');
        card.className = 'analysis-card bg-gray-800 border border-gray-700 rounded-lg p-4 shadow-lg';
        
        const analysesHTML = data.analyses.map(createAnalysisHTML).join('');

        card.innerHTML = `
            <div class="flex justify-between items-center mb-2">
                <p class="text-sm font-mono text-gray-500">${data.process}</p>
                <p class="text-xs font-mono text-gray-500">${new Date(data.timestamp).toLocaleString()}</p>
            </div>
            <p class="font-mono text-gray-300 bg-gray-900 p-3 rounded mb-4">${data.log}</p>
            <div class="space-y-3">
                ${analysesHTML}
            </div>
        `;
        
        // Вставляем новую карточку в начало ленты
        logFeed.prepend(card);
        
        // Плавное появление
        setTimeout(() => card.classList.add('visible'), 50);

        // Ограничиваем количество карточек в ленте, чтобы не перегружать DOM
        if (logFeed.children.length > 100) {
            logFeed.removeChild(logFeed.lastChild);
        }
    }
});
