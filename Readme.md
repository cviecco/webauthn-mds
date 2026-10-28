### Webauthn-mds

This is a repository to be used to create go-webathhn compatible metadata providers.
As part of building a tool I noticed that the the fido metadata url fetches
were very unreliable and thus a need for a built-in medatada provider was noticed.

Currenly we only support fido2 mds data provider, and use gz compression to minimize
the embeded size both for git and for the embedders.


