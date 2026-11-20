# Deploying

3. Paste your origin certificate and its private key into the proxy:

   ```
   $EDITOR proxy/certs/origin.pem      # -----BEGIN CERTIFICATE-----
   $EDITOR proxy/certs/origin.key      # -----BEGIN PRIVATE KEY-----
   ```

   Both files are listed in `.gitignore`, so they stay on the server and are
   never committed.
