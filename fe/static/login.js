document.getElementById('loginForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const messageElement = document.getElementById('responseMessage');

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        const data = await response.json();

        if (response.ok) {
            messageElement.style.color = 'green';
            messageElement.textContent = data.message;
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1000);
        } else {
            messageElement.style.color = 'red';
            messageElement.textContent = data.message;
        }
    } catch (error) {
        messageElement.style.color = 'red';
        messageElement.textContent = `An error occurred: ${error.message}`;
    }
});
