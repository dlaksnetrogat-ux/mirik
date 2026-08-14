(() => {
    const root = document.documentElement;

    function setTheme(theme) {
        const next = theme === 'dark' ? 'dark' : 'light';
        root.dataset.theme = next;
        try { localStorage.setItem('mirik-theme', next); } catch (_) {}
    }

    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
        button.addEventListener('click', () => {
            setTheme(root.dataset.theme === 'dark' ? 'light' : 'dark');
        });
    });

    const search = document.getElementById('chat-search');
    const chatList = document.getElementById('chat-list');
    if (search && chatList) {
        search.addEventListener('input', () => {
            const query = search.value.trim().toLowerCase();
            chatList.querySelectorAll('[data-chat-name]').forEach((item) => {
                item.hidden = query !== '' && !item.dataset.chatName.includes(query);
            });
        });
    }

    const modal = document.querySelector('[data-modal]');
    const openModalButtons = document.querySelectorAll('[data-new-chat]');
    const closeModalButton = document.querySelector('[data-modal-close]');

    const setModal = (open) => {
        if (!modal) return;
        modal.hidden = !open;
        document.body.classList.toggle('modal-open', open);
        if (open) {
            const firstInput = modal.querySelector('input[name="chat_name"]');
            if (firstInput) setTimeout(() => firstInput.focus(), 30);
        }
    };

    openModalButtons.forEach((button) => button.addEventListener('click', () => setModal(true)));
    if (closeModalButton) closeModalButton.addEventListener('click', () => setModal(false));
    if (modal) {
        modal.addEventListener('click', (event) => {
            if (event.target === modal) setModal(false);
        });
    }
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && modal && !modal.hidden) setModal(false);
    });

    document.querySelectorAll('[data-copy-code]').forEach((button) => {
        button.addEventListener('click', async () => {
            const code = button.dataset.copyCode;
            try {
                await navigator.clipboard.writeText(code);
                const original = button.textContent;
                button.textContent = '✓ Скопировано';
                setTimeout(() => { button.textContent = original; }, 1200);
            } catch (_) {
                // Clipboard access can be unavailable on plain HTTP/local files.
            }
        });
    });

    const messages = document.getElementById('messages');
    if (messages) messages.scrollTop = messages.scrollHeight;
})();
