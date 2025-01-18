document.addEventListener('DOMContentLoaded', function() {
    const chatMessages = document.getElementById('chat-messages');
    const messageForm = document.querySelector('.chat-input form');
    const messageInput = messageForm.querySelector('input[name="content"]');

    // Scroll to bottom on load
    chatMessages.scrollTop = chatMessages.scrollHeight;

    // Handle message submission
    messageForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        if (messageInput.value.trim() !== '') {
            // Send message via form
            this.submit();
        }
    });

    // Handle input key press
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            messageForm.dispatchEvent(new Event('submit'));
        }
    });
});
 