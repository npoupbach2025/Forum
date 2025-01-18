document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');
    
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        // Validation basique
        if (!username || !password) {
            alert('Veuillez remplir tous les champs');
            return;
        }
        
        // En conditions réelles, envoyez à votre backend Django
        this.submit();
    });
    
    // Animation des labels
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', function() {
            if (!this.value) {
                this.parentElement.classList.remove('focused');
            }
        });
        
        // Pour conserver le style si le champ est pré-rempli
        if (input.value) {
            input.parentElement.classList.add('focused');
        }
    });
});