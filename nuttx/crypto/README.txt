Nuttx Crypto Library
Sebastien Lorquet, 2014

This is a library to access cryptographic ressources ala PKCS#11

Modules are able to run algs and store keys
Contexts can be opened with modules after authentication.

Implementation notes

Module management does not have to be fast:
Module list creation only happens at boot
Module lookup only happens when a session is created

Session list management has to be fast:
Session list is accessed every time a crypto action happens.
So, all sessions are in a linked list, but we keep the most recently accessed sessions in a small cache

Session list is global, each module does NOT hold the sessions opened with it.
The number of sessions and module is predicted to stay small, no performance penalty is expected.
If performance is needed, then some mechanisms will be added later.

