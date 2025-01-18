document.addEventListener('DOMContentLoaded', function() {
    initializeAccessTypeHandling();
    initializeMemberSearch();
});

function initializeAccessTypeHandling() {
    const accessType = document.getElementById('access-type');
    const passwordSection = document.querySelector('.password-section');
    
    if (accessType && passwordSection) {
        accessType.addEventListener('change', function() {
            passwordSection.style.display = this.value === 'password' ? 'block' : 'none';
        });
    }
}

function initializeMemberSearch() {
    const searchInput = document.getElementById('member-search');
    
    if (searchInput) {
        searchInput.addEventListener('input', debounce(function() {
            if (this.value.length >= 2) {
                searchMembers(this.value);
            }
        }, 300));
    }
}

async function searchMembers(query) {
    try {
        const response = await fetch(`/api/search-members?q=${encodeURIComponent(query)}`, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            displaySearchResults(data);
        }
    } catch (error) {
        console.error('Erreur lors de la recherche:', error);
    }
}

function displaySearchResults(results) {
    // Création des éléments de résultats de recherche
    const searchResults = document.createElement('div');
    searchResults.className = 'search-results';
    
    results.forEach(user => {
        const userElement = document.createElement('div');
        userElement.className = 'search-result-item';
        userElement.innerHTML = `
            <span>${user.username}</span>
            <button type="button" onclick="addMember('${user.id}', '${user.username}')">
                Ajouter
            </button>
        `;
        searchResults.appendChild(userElement);
    });
    
    // Remplacer les résultats existants
    const existingResults = document.querySelector('.search-results');
    if (existingResults) {
        existingResults.replaceWith(searchResults);
    } else {
        document.querySelector('.members-search').appendChild(searchResults);
    }
}

function addMember(userId, username) {
    const memberList = document.getElementById('member-list');
    // Vérifier si le membre n'est pas déjà dans la liste
    if (!document.querySelector(`input[value="${userId}"]`)) {
        const memberItem = document.createElement('li');
        memberItem.innerHTML = `
            <span>${username}</span>
            <input type="hidden" name="members[]" value="${userId}">
            <button type="button" onclick="removeMember(this)">
                <i class="fas fa-times"></i>
            </button>
        `;
        memberList.appendChild(memberItem);
    }
}

function removeMember(button) {
    button.closest('li').remove();
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            timeout = null;
            func.apply(this, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}