```mermaid
stateDiagram-v2
    [*] --> NonAuthenticated
    NonAuthenticated --> Authenticated: Login
    Authenticated --> NonAuthenticated: Logout

    state Authenticated {
        [*] --> Active
        Active --> Banned: Violation
        Banned --> Active: UnBan
        Active --> Inactive: Inactivity
        Inactive --> Active: Login

        state Active {
            [*] --> Normal
            Normal --> Moderator: Promotion
            Moderator --> Admin: Promotion
            Admin --> Moderator: Demotion
            Moderator --> Normal: Demotion
        }
    }

    state Topic {
        [*] --> Draft
        Draft --> Published: Publish
        Published --> Closed: Close
        Published --> Deleted: Delete
        Closed --> Published: Reopen
        Closed --> Deleted: Delete
    }

    state UserProfile {
        [*] --> Unverified
        Unverified --> Verified: Email Verification
        Verified --> TwoFactorEnabled: Enable 2FA
        TwoFactorEnabled --> Verified: Disable 2FA
    }
```
