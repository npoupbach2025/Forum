document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('newTopicModal');
    const closeBtn = modal.querySelector('.close');
    const publicForm = document.getElementById('publicForumForm');
    const privateForm = document.getElementById('privateForumForm');

    // Fermer le modal
    closeBtn.onclick = function() {
        modal.style.display = "none";
    }

    // Fermer si clic en dehors du modal
    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }
});

function showForm(type) {
    const modal = document.getElementById('newTopicModal');
    const publicForm = document.getElementById('publicForumForm');
    const privateForm = document.getElementById('privateForumForm');
    
    modal.style.display = "block";
    
    if (type === 'public') {
        publicForm.style.display = "block";
        privateForm.style.display = "none";
    } else {
        publicForm.style.display = "none";
        privateForm.style.display = "block";
    }
}