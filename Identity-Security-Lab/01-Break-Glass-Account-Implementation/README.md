# Break Glass Account Implementation

## Objective
Design and manage emergency access accounts to ensure business continuity during identity provider outages, authentication failures, or conditional access misconfigurations.

## Key Considerations
- Cloud-only emergency account using the tenant's default onmicrosoft.com domain
- Excluded from Conditional Access policies
- Long and complex password (32+ characters)
- Secure offline secret storage or vaulting
- Continuous monitoring and alerting
- Periodic access review and validation

## Security Controls
- Sign-in monitoring with alerts for any activity
- Highly restricted privileged role assignment
- Audit logging enabled and reviewed regularly
- Documented incident response procedures for emergency access usage

## Lessons Learned
- Minimize standing privilege wherever possible
- Regularly validate emergency access procedures
- Monitor all sign-ins and investigate any usage immediately
