1. create stack
    - you are using git pull method (not zip)
    - AllowedIps: i put 192.30.252.0/22 from https://api.github.com/meta here but maybe it is not necessary
    - ApiSecret generate something random
    
2. github -> repo -> settings -> Deploy keys (rsa from output of webhooks stack)
3. github -> repo -> settings -> webhooks -> create new
    - payload url from output of webhooks stack
    - content type application/json
    - Secret that you generated in step 1 