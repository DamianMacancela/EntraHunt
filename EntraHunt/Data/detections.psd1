@{
    SignIn = @{
        Spray = @{
            WindowMinutes    = 10
            MinDistinctUsers = 3
            HighThreshold    = 5
        }
        BruteForce = @{
            WindowMinutes = 10
            MinFailures   = 10
        }
        SuccessAfterFailure = @{
            FailureThreshold = 3
            WindowMinutes    = 30
        }
        ImpossibleTravel = @{
            WindowHours = 2
        }
        MFAFatigue = @{
            ErrorCode        = 500121
            Threshold        = 5
            WindowMinutes    = 30
            LookAheadMinutes = 30
        }
    }
    InboxRule = @{
        FinancialKeywords = @(
            'invoice', 'payment', 'transfer', 'wire', 'bank',
            'payroll', 'expense', 'finance', 'remittance'
        )
        AllowedForwardDomains = @()
    }
    OAuth = @{
        HighRiskScopes = @(
            'Files.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send',
            'User.ReadWrite.All', 'Directory.ReadWrite.All',
            'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All',
            'full_access_as_user', 'EWS.AccessAsUser.All'
        )
        MediumRiskScopes = @(
            'Files.Read.All', 'Mail.Read', 'Contacts.Read',
            'User.Read.All', 'Directory.Read.All', 'MailboxSettings.Read',
            'Sites.Read.All', 'GroupMember.Read.All'
        )
        NewAppDays = 30
    }
    ModernClientApps = @(
        'Browser',
        'Mobile Apps and Desktop Clients'
    )
}
