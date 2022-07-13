# How to set up SMTP?

The goal of setting up SMTP is to allow your Vocechat server sending emails to your Vocechat members (e.g., to verify emails during new members signing up)

With vocechat-server launched, visit your vocechat domain (http://localhost:3000/ if you are testing it locally), login with administrator account, click the "Settings" button in the lower left corner, go to the "SMTP Setting" page, snapshot as follows:
![smtp-setting.jpg](image/smtp-setting.jpg)

## Enable Gmail SMTP.
1. sign in https://gmail.com/ .
2. Enable "Less secure app access"
   > Less Secure Apps (Admin Side): https://admin.google.com/ac/security/lsa  
   > Less Secure Apps (Inbox Side): https://myaccount.google.com/lesssecureapps?pli=1
3. ![smtp-gmail.jpg](image/smtp-gmail.jpg)
