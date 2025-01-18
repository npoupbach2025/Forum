// static/forum/js/moderation-users.js

document.addEventListener('DOMContentLoaded', function() {
    // Éléments DOM
    const userSearch = document.getElementById('userSearch');
    const userFilter = document.getElementById('userFilter');
    const editModal = document.getElementById('editUserModal');
    const editForm = document.getElementById('editUserForm');
    const closeModalBtn = editModal.querySelector('.close');
    
    // Fonction de recherche
    function filterUsers() {
        const searchTerm = userSearch.value.toLowerCase();
        const filterValue = userFilter.value;
        const rows = document.querySelectorAll('#usersTable tbody tr');
        
        rows.forEach(row => {
            const username = row.querySelector('.username').textContent.toLowerCase();
            const email = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
            const status = row.querySelector('.status-badge').classList;
            
            const matchesSearch = username.includes(searchTerm) || email.includes(searchTerm);
            const matchesFilter = filterValue === 'all' || status.contains(filterValue);
            
            row.style.display = matchesSearch && matchesFilter ? '' : 'none';
        });
    }
    
    // Gestionnaire de recherche
    userSearch.addEventListener('input', filterUsers);
    userFilter.addEventListener('change', filterUsers);
    
    // Gestion du modal d'édition
    function openEditModal(userId) {
        const row = document.querySelector(`tr[data-user-id="${userId}"]`);
        const username = row.querySelector('.username').textContent;
        const email = row.querySelector('td:nth-child(2)').textContent;
        const status = row.querySelector('.status-badge').classList.contains('mod') ? 'mod' : 'user';
        
        document.getElementById('editUserId').value = userId;
        document.getElementById('editUsername').value = username;
        document.getElementById('editEmail').value = email;
        document.getElementById('editStatus').value = status;
        
        editModal.style.display = 'block';
    }
    
    // Gestionnaires d'événements pour le modal
    document.querySelectorAll('.edit-user-btn').forEach(btn => {
        btn.addEventListener('click', () => openEditModal(btn.dataset.userId));
    });
    
    closeModalBtn.addEventListener('click', () => {
        editModal.style.display = 'none';
    });
    
    window.addEventListener('click', (e) => {
        if (e.target === editModal) {
            editModal.style.display = 'none';
        }
    });
    
    // Gestion de la soumission du formulaire d'édition
    editForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = new FormData(this);
        const userId = formData.get('user_id');
        
        try {
            const response = await fetch(`/mod/users/${userId}/edit/`, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                updateUserRow(userId, data);
                editModal.style.display = 'none';
            } else {
                alert('Une erreur est survenue lors de la modification.');
            }
        } catch (error) {
            console.error('Erreur:', error);
            alert('Une erreur est survenue.');
        }
    });
    
    // Gestion de la suppression
    document.querySelectorAll('.delete-user-form').forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur ?')) {
                e.preventDefault();
            }
        });
    });
    
    // Mise à jour de la ligne utilisateur après édition
    function updateUserRow(userId, userData) {
        const row = document.querySelector(`tr[data-user-id="${userId}"]`);
        if (row) {
            row.querySelector('.username').textContent = userData.username;
            row.querySelector('td:nth-child(2)').textContent = userData.email;
            
            const statusBadge = row.querySelector('.status-badge');
            statusBadge.className = 'status-badge ' + userData.status;
            statusBadge.textContent = userData.status === 'mod' ? 'Modérateur' : 'Utilisateur';
        }
    }
});