// Gestion des modaux
function openReportModal() {
    document.getElementById('reportModal').style.display = 'block';
}

function closeReportModal() {
    document.getElementById('reportModal').style.display = 'none';
}

// Assurez-vous que le formulaire de signalement est soumis correctement
document.addEventListener('DOMContentLoaded', function() {
    const reportForm = document.querySelector('#reportModal form');
    if (reportForm) {
        reportForm.addEventListener('submit', function(e) {
            if (!this.reason.value) {
                e.preventDefault();
                alert('Veuillez sélectionner une raison pour le signalement.');
            }
        });
    }
});

function openEditModal() {
    document.getElementById('editModal').style.display = 'block';
}

function closeEditModal() {
    document.getElementById('editModal').style.display = 'none';
    document.getElementById('editForm').reset();
}

// Fermer les modaux si on clique en dehors
window.onclick = function(event) {
    const reportModal = document.getElementById('reportModal');
    const editModal = document.getElementById('editModal');
    if (event.target == reportModal) {
        closeReportModal();
    }
    if (event.target == editModal) {
        closeEditModal();
    }
}

// Gestion du scroll automatique
function scrollToBottom() {
    const messagesList = document.getElementById('messagesList');
    messagesList.scrollTop = messagesList.scrollHeight;
}

// Scroll au chargement de la page
document.addEventListener('DOMContentLoaded', function() {
    scrollToBottom();
});

// Gestion du formulaire de réponse
const replyForm = document.getElementById('replyForm');
if (replyForm) {
    replyForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const messageInput = document.getElementById('messageInput');
        const content = messageInput.value.trim();
        
        if (!content) return;

        try {
            const response = await fetch(this.action, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                },
                body: new URLSearchParams(new FormData(this))
            });

            if (response.ok) {
                messageInput.value = '';
                const data = await response.json();
                if (data.html) {
                    const messagesList = document.getElementById('messagesList');
                    messagesList.insertAdjacentHTML('beforeend', data.html);
                    scrollToBottom();
                }
            }
        } catch (error) {
            console.error('Erreur:', error);
        }
    });
}

// Gestion de l'édition des commentaires
async function editComment(commentId) {
    const contentElement = document.getElementById(`comment-content-${commentId}`);
    const content = contentElement.innerText;
    
    const editContent = document.getElementById('editContent');
    editContent.value = content;
    
    const editForm = document.getElementById('editForm');
    editForm.setAttribute('data-comment-id', commentId);
    
    openEditModal();
}

// Formulaire d'édition
const editForm = document.getElementById('editForm');
if (editForm) {
    editForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const commentId = this.getAttribute('data-comment-id');
        const content = document.getElementById('editContent').value;
        
        try {
            const response = await fetch(`/comment/${commentId}/edit/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                },
                body: `content=${encodeURIComponent(content)}`
            });

            if (response.ok) {
                const data = await response.json();
                document.getElementById(`comment-content-${commentId}`).innerText = content;
                closeEditModal();
            }
        } catch (error) {
            console.error('Erreur:', error);
        }
    });
}

// Suppression des commentaires
function deleteComment(commentId) {
    if (confirm('Êtes-vous sûr de vouloir supprimer ce message ?')) {
        fetch(`/comment/${commentId}/delete/`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
            }
        })
        .then(response => {
            if (response.ok) {
                document.getElementById(`message-${commentId}`).remove();
            }
        })
        .catch(error => console.error('Erreur:', error));
    }
}

// Confirmation de suppression du topic
function confirmDelete() {
    if (confirm('Êtes-vous sûr de vouloir supprimer cette discussion ?')) {
        // Rediriger vers l'URL de suppression
        window.location.href = `${window.location.pathname}/delete/`;
    }
}

// Rafraîchissement automatique des messages
let lastUpdate = new Date();

async function checkNewMessages() {
    const topicId = window.location.pathname.split('/').filter(Boolean).pop();
    try {
        const response = await fetch(`/topic/${topicId}/messages?after=${lastUpdate.toISOString()}`);
        if (response.ok) {
            const data = await response.json();
            if (data.messages && data.messages.length > 0) {
                data.messages.forEach(message => {
                    if (!document.getElementById(`message-${message.id}`)) {
                        const messagesList = document.getElementById('messagesList');
                        messagesList.insertAdjacentHTML('beforeend', message.html);
                    }
                });
                scrollToBottom();
                lastUpdate = new Date();
            }
        }
    } catch (error) {
        console.error('Erreur lors de la vérification des nouveaux messages:', error);
    }
}

// Vérifier les nouveaux messages toutes les 10 secondes
setInterval(checkNewMessages, 10000);

// Gestion des raccourcis clavier
document.addEventListener('keydown', function(e) {
    const messageInput = document.getElementById('messageInput');
    
    // Entrée pour envoyer le message
    if (e.key === 'Enter' && !e.shiftKey && document.activeElement === messageInput) {
        e.preventDefault();
        replyForm.dispatchEvent(new Event('submit'));
    }
    
    // Échap pour fermer les modaux
    if (e.key === 'Escape') {
        closeReportModal();
        closeEditModal();
    }
});