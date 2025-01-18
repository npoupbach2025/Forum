```mermaid
graph TB
    subgraph Actors
        User((User))
        Moderator((Moderator))
        Admin((Admin))
    end

    subgraph Authentication
        Register[Register]
        Login[Login]
        Logout[Logout]
        ResetPassword[Reset Password]
        Enable2FA[Enable 2FA]
    end

    subgraph Forum Management
        CreateTopic[Create Topic]
        EditTopic[Edit Topic]
        DeleteTopic[Delete Topic]
        AddComment[Add Comment]
        EditComment[Edit Comment]
        DeleteComment[Delete Comment]
        ReportContent[Report Content]
    end

    subgraph Moderation
        ManageUsers[Manage Users]
        ManageTopics[Manage Topics]
        HandleReports[Handle Reports]
        BanUser[Ban User]
        DeleteUser[Delete User]
    end

    subgraph Administration
        ManageCategories[Manage Categories]
        ManageModerators[Manage Moderators]
        ViewStats[View Statistics]
        SystemSettings[System Settings]
    end

    User --> Authentication
    User --> Forum Management
    Moderator --> Forum Management
    Moderator --> Moderation
    Admin --> Forum Management
    Admin --> Moderation
    Admin --> Administration
```
