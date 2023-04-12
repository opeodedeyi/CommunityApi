const nodemailer = require('nodemailer')
const jwt = require('jsonwebtoken')
require('dotenv').config()


const name = process.env.COMPANY_NAME
const email = process.env.NODEMAILER_EMAIL
const password = process.env.NODEMAILER_PASS
const website = process.env.COMPANY_WEBSITE


var transporter = nodemailer.createTransport({
    host: "smtpout.secureserver.net",  
    secure: true,
    secureConnection: false, // TLS requires secureConnection to be false
    tls: {
        ciphers:'SSLv3'
    },
    requireTLS:true,
    port: 465,
    debug: true,
    auth: {
        user: email,
        pass: password
    }
});


const sendConfirmationEmail = async (user) => {

    const token = await jwt.sign({ 
        _id: user._id.toString() 
    }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' })

    const url = `https://${website}/confirmation/${token}`

    transporter.sendMail({
        from: `${name} <${email}>`,
        to: `${user.fullname} <${user.email}>`,
        subject: 'Verify Your Email',
        html: `
            <!DOCTYPE html>
            <html>
            <header>
                <title>Confirmation email</title>
            </header>
            
            <body style="background-color: #E9ECF2;">
            <center>
                <table style="color: #627085;
                            font-family: 'ProximaNova-Regular', Helvetica, Arial, sans-serif;
                            max-width:500px;">
            
                </table>
                <table style="background-color: #fff;
                                font-family: 'ProximaNova-Regular', Helvetica, Arial, sans-serif;
                                font-size: 0.9rem;
                                color: #627085;
                                max-width:500px;
                                border-radius:4px;
                                margin: 20px 20px 20px 20px;
                                padding: 40px;
                                box-shadow:0 1px 3px #B7C0CC, 0 1px 2px #B7C0CC;">
                <tr>
                    <td style="font-size: 1.4rem;
                    padding-top:20px;padding-bottom:20px;">Please confirm your email!</td>
                </tr>
                <tr>
                    <td style="padding-top:20px;padding-bottom:20px;padding-bottom:20px;margin-bottom:10px;">Hey ${user.fullname},</td>
                </tr>
                <tr style="padding-top:5px;padding-bottom:20px;">
                    <td style="padding-bottom:10px;margin-bottom:10px;">We're excited to have you get started. First, you need to confirm your account. Just press the button below and get verified. The link will expire in 1 hour.</td>
                </tr>
                    
                <tr style="padding-top:40px;padding-bottom:30px;">
                    <td style="padding-bottom:10px;margin-bottom:10px;">Sincerely,</td>
                </tr>
                <tr><td>${process.env.COMPANY_NAME}</td></tr>
                <tr>
                    <td style="padding-top:40px;"><a href="${url}"><input value="Confirm Email" type="button" style="background: #4D69B4;
                    padding: 15px 40px;
                    border-radius: 22.2px;
                    border: none;
                    color:#fff;
                    font-size:0.9rem;
                    cursor:pointer"/>
                    </a>
                    </td>
                </tr>
                </table>
            </center>
            </body>
            
            </html>
        `
    }).then( () => {
        console.log('Email Sent');
    }).catch( () => {
        console.log('Email not sent');
    })
}


const sendPasswordResetEmail = async (user) => {

    const token = await jwt.sign({ 
        _id: user._id.toString() 
    }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' })

    const url = `https://${website}/resetpassword/${token}`

    transporter.sendMail({
        from: `${name} <${email}>`,
        to: `${user.fullname} <${user.email}>`,
        subject: `Reset Your Password`,
        html: `
            <!DOCTYPE html>
            <html>
            <header>
                <title>Password reset</title>
            </header>
            
            <body style="background-color: #E9ECF2;">
            <center>
                <table style="color: #627085;
                            font-family: 'ProximaNova-Regular', Helvetica, Arial, sans-serif;
                            max-width:500px;">
            
                </table>
                <table style="background-color: #fff;
                                font-family: 'ProximaNova-Regular', Helvetica, Arial, sans-serif;
                                font-size: 0.9rem;
                                color: #627085;
                                max-width:500px;
                                border-radius:4px;
                                margin: 20px 20px 20px 20px;
                                padding: 40px;
                                box-shadow:0 1px 3px #B7C0CC, 0 1px 2px #B7C0CC;">
                <tr>
                    <td style="padding-top:20px;
                            padding-bottom:10px;">Hey ${user.fullname},</td>
                </tr>
                <tr>
                    <td style="font-size: 1.4rem;
                    padding-top:20px;padding-bottom:20px;margin-bottom:20px;">You have requested to reset your password</td>
                </tr>
                
                <tr style="padding-top:20px;padding-bottom:20px;margin-bottom:20px;">
                    <td style="padding-bottom:10px;margin-bottom:10px;">A unique link to reset your password has been generated for you. To reset your password, click the following button below and follow the instructions. The link will expire in 24 hours.</td>
                </tr>

                <tr style="padding-top:20px;padding-bottom:20px;margin-bottom:20px;">
                    <td style="padding-bottom:10px;margin-bottom:10px;">If you didnt request this to reset your password, Please ignore this message.</td>
                </tr>
                    
                <tr style="padding-top:40px;padding-bottom:30px;">
                    <td>Sincerely,</td>
                </tr>
                <tr><td>${process.env.COMPANY_NAME}</td></tr>
                <tr>
                    <td style="padding-top:40px;"><a href="${url}"><input value="Reset Password" type="button" style="background: #4D69B4;
                    padding: 15px 40px;
                    border-radius: 22.2px;
                    border: none;
                    color:#fff;
                    font-size:0.9rem;
                    cursor:pointer;" />
                    </a>
                    </td>
                </tr>
                </table>
            </center>
            </body>
            
            </html>
        `
    }).then( () => {
        console.log('Email Sent');
    }).catch( () => {
        console.log('Email not sent');
    })
}


const reportUser = async (user, repo, body) => {

  transporter.sendMail({
      from: `${name} <${email}>`,
      to: `${process.env.COMPANY_NAME} <lookaamdotcom@gmail.com>`,
      subject: `Report a user`,
      html: `
          <!DOCTYPE html>
          <html>
          <header>
            <title>Event center</title>
          </header>
          
          <body style="background-color: #E9ECF2;">
            <center>
              <table style="color: #627085;
                            font-family: 'ProximaNova-Regular', Helvetica, Arial, sans-serif;
                            max-width:500px;">
          
              </table>
              <table style="background-color: #fff;
                              font-family: 'ProximaNova-Regular', Helvetica, Arial, sans-serif;
                              font-size: 0.9rem;
                              color: #627085;
                              max-width:500px;
                              border-radius:4px;
                              margin: 20px 20px 20px 20px;
                              padding: 40px;
                              box-shadow:0 1px 3px #B7C0CC, 0 1px 2px #B7C0CC;">
                <tr>
                  <td style="font-size: 1.4rem;
                    padding-top:20px;padding-bottom:20px;">${repo.email}</td>
                </tr>
                <tr>
                  <td style="padding-top:20px;
                            padding-bottom:10px;">Hello There,</td>
                </tr>
                <tr style="padding-top:5px;padding-bottom:20px;">
                  <td style="padding-bottom:20px;margin-bottom:20px;">
                    ${body}
                  </td>
                </tr
                  
                <tr style="padding-top:40px;padding-bottom:30px;">
                  <td style="padding-bottom:10px;margin-bottom:10px;">Sincerely, ${process.env.COMPANY_NAME}</td>
                </tr>
                <tr><td style="padding-bottom:10px;margin-bottom:10px;">${repo.fullname}</td></tr>
              </table>
            </center>
          </body>
          
          </html>
      `
  }).then( () => {
      console.log('Email Sent');
  }).catch( () => {
      console.log('Email not sent');
  })
}


module.exports = {
    sendConfirmationEmail,
    sendPasswordResetEmail,
    reportUser
};
