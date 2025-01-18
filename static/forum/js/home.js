document.addEventListener('DOMContentLoaded', function() {
    // Éléments DOM
    const privateMessageModal = document.getElementById('privateMessageModal');
    const newPrivateMessageBtn = document.getElementById('newPrivateMessageBtn');
    const closeButtons = document.querySelectorAll('.close');
    const privateMessageForm = document.getElementById('privateMessageForm');
    const deleteChatButtons = document.querySelectorAll('.delete-chat');
    

    // Gestion de la modal de message privé
    if (newPrivateMessageBtn) {
        newPrivateMessageBtn.onclick = function() {
            privateMessageModal.style.display = 'block';
        }
    }

    // Fermeture des modales
    closeButtons.forEach(button => {
        button.onclick = function() {
            privateMessageModal.style.display = 'none';
        }
    });

    // Fermer la modale en cliquant en dehors
    window.onclick = function(event) {
        if (event.target === privateMessageModal) {
            privateMessageModal.style.display = 'none';
        }
    }

    // Gestion du formulaire de message privé
    if (privateMessageForm) {
        privateMessageForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            
            try {
                const response = await fetch(this.action, {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-CSRFToken': formData.get('csrfmiddlewaretoken')
                    }
                });
                
                const data = await response.json();
                
                if (data.success) {
                    // Fermer la modale
                    privateMessageModal.style.display = 'none';
                    
                    // Ajouter la nouvelle discussion à la liste
                    const channelCategory = document.querySelector('.sidebar-section');
                    if (channelCategory) {
                        const newChannel = createChannelElement(data);
                        channelCategory.appendChild(newChannel);
                    }
                    
                    // Rediriger vers la nouvelle discussion
                    window.location.href = `/chat/${data.chat_id}`;
                } else {
                    alert(data.error || 'Une erreur est survenue lors de la création de la discussion');
                }
            } catch (error) {
                console.error('Erreur:', error);
                alert('Une erreur est survenue lors de la création de la discussion');
            }
        });
    }

    // Gestion de la suppression des chats
    deleteChatButtons.forEach(button => {
        button.addEventListener('click', async function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            if (confirm('Voulez-vous vraiment supprimer cette conversation ?')) {
                const chatId = this.dataset.chatId;
                try {
                    const response = await fetch(`/chat/${chatId}/delete/`, {
                        method: 'POST',
                        headers: {
                            'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                        }
                    });
                    
                    const data = await response.json();
                    if (data.success) {
                        // Supprimer l'élément du DOM
                        this.closest('.channel').remove();
                        
                        // Vérifier s'il reste des conversations
                        const remainingChannels = document.querySelectorAll('.channel');
                        if (remainingChannels.length === 0) {
                            const messageSection = document.querySelector('.sidebar-section');
                            if (messageSection) {
                                messageSection.innerHTML += '<p class="text-muted p-3">Aucune conversation</p>';
                            }
                        }
                    }
                } catch (error) {
                    console.error('Erreur:', error);
                    alert('Une erreur est survenue lors de la suppression de la discussion');
                }
            }
        });
    });

    // Fonction utilitaire pour créer un nouvel élément de canal
    function createChannelElement(data) {
        const channel = document.createElement('div');
        channel.className = 'channel';
        channel.innerHTML = `
            <div class="channel-content">
                <a href="/chat/${data.chat_id}" class="nav-link">
                    <i class="fas fa-user"></i>
                    ${data.friend_username}
                </a>
                <button class="delete-chat" data-chat-id="${data.chat_id}" title="Supprimer la conversation">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        // Ajouter l'écouteur d'événement pour le nouveau bouton de suppression
        const deleteButton = channel.querySelector('.delete-chat');
        if (deleteButton) {
            deleteButton.addEventListener('click', handleDeleteChat);
        }

        return channel;
    }

    // Gestionnaire d'événement pour la suppression de chat
    async function handleDeleteChat(e) {
        e.preventDefault();
        e.stopPropagation();
        
        if (confirm('Voulez-vous vraiment supprimer cette conversation ?')) {
            const chatId = this.dataset.chatId;
            try {
                const response = await fetch(`/chat/${chatId}/delete/`, {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                    }
                });
                
                const data = await response.json();
                if (data.success) {
                    this.closest('.channel').remove();
                }
            } catch (error) {
                console.error('Erreur:', error);
                alert('Une erreur est survenue lors de la suppression de la discussion');
            }
        }
    }
});