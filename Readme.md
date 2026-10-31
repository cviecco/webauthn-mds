# Webauthn-mds

This is a repository to be used to create go-webathhn compatible metadata providers.
As part of building a tool I noticed that the the fido metadata url fetches
were very unreliable and thus a need for a built-in medatada provider was noticed.

Currenly we only support fido2 mds data provider, and use gz compression to minimize
the embeded size both for git and for the embedders. The data here is a good first approximation as event the fido alliance license removes any liability on the correctness of the data. 


## License and Copyrights
This repository contains a mix of files with different licenses. Please be aware:
* All source code is licenced with APL-2.0

fido metadata (metadata.jwt.gz) is copyrighted by the fido alliance.; nd is being used in this repo by following the [Developers Agreement](https://fidoalliance.org/wp-content/uploads/2022/08/MetadataUsageDeveloperTerms_Revised_MDS3_08020222.pdf). And the file in question is subject to [retrieval terms](https://fidoalliance.org/metadata/metadata-legal-terms/).  This agreement can be summarized as:
1. Keep the data up to date.
2. Ensure copyright is kept and you dont change the notices
3. No guarantee or idemnization of tha data. (In other words you cannot sue us becuase of use of this data.)






