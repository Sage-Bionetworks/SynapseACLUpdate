# SynapseACLUpdate
ACL Update to fulfill PLFM-4258

The list of ACL IDs to update is in /path/to/owner_id.txt

to run:
```
docker run --rm -it \
-e STAGING=true -e SYNAPSE_USERNAME=XXX -e SYNAPSE_PASSWORD=XXX \
-v /path/to/owner_id.txt:/owner_id.txt brucehoff/synapseaclupdate
```
using the credentials for a synapse administrator
