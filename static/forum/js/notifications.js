class NotificationManager {
    constructor() {
        this.init();
    }

    init() {
        // Demander la permission pour les notifications si ce n'est pas déjà fait
        if (Notification.permission !== 'granted' && Notification.permission !== 'denied') {
            this.requestPermission();
        }
    }

    async requestPermission() {
        try {
            const permission = await Notification.requestPermission();
            if (permission === 'granted') {
                console.log('Notification permission granted');
            }
        } catch (error) {
            console.error('Error requesting notification permission:', error);
        }
    }

    showNotification(title, options = {}) {
        if (Notification.permission === 'granted') {
            const defaultOptions = {
                icon: '/static/forum/img/logo.png',
                badge: '/static/forum/img/logo.png',
                vibrate: [200, 100, 200],
                ...options
            };

            try {
                new Notification(title, defaultOptions);
            } catch (error) {
                console.error('Error showing notification:', error);
            }
        }
    }

    showTopicNotification(topicTitle, author) {
        this.showNotification('Nouvelle discussion', {
            body: `${author} a créé une nouvelle discussion : ${topicTitle}`,
            tag: 'new-topic'
        });
    }

    showCommentNotification(topicTitle, author) {
        this.showNotification('Nouveau commentaire', {
            body: `${author} a commenté dans : ${topicTitle}`,
            tag: 'new-comment'
        });
    }
}

// Créer une instance globale
window.notificationManager = new NotificationManager();
