---
title: "Permissions: ACE/SDDL - Format"
date: 2025-10-03
draft: false
type: wiki
---

* ACE (Access Control Enties)
* SDDL (Security Descriptor Definition Language)

```console
ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid

--> ace_type: defines allow/deny/audit
--> ace_flags: inheritance objects
--> rights: incremental list with given permissions (allowed/audited/denied), incrmentalas ARE NOT the only ones
--> object_guid and inherit_object: Allows to apply an ACE on a specified objects by GUID values. GUID is an object class, attribute, set or extended right, if pressent limits the ACE's to the object the GUID represents. Inherited GUID represents an object class, if present will limit the inheritance of ACE's to the child enties only of that object
--> account_sid: SID of the object the ACE is applying, is the SID of the user or group to the one permissions are being assigned, sometimes there are acronyms of well known SID's instead of numerical ones
```

-----------------------------
