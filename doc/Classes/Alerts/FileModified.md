# FileModified extends [HaliteAlert](HaliteAlert.md)

**Namespace**: `\ParagonIE\Halite\Alerts`

This indicates a race condition was being exploited against your app. This 
happens when a file you were attempting to decrypt was modified after it was
opened for decryption.

There are a few possible causes to consider:

* Cloud storage apps (DropBox, Google Drive, etc.)
* Malware
* Filesystem bugs
* Hardware errors
