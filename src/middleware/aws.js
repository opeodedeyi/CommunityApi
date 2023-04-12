// Load environment variables from the .env file
require('dotenv').config();

// Import the AWS SDK and extract the S3 class
const { S3 } = require('aws-sdk');

// Initialize a new S3 instance using the access key and secret access key from environment variables
const s3 = new S3({
  accessKeyId: process.env.AWS_ID,
  secretAccessKey: process.env.AWS_SECRET,
});

// Export the S3 instance for use in other parts of the application
module.exports = {
  s3,
};
