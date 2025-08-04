const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
// You'll need to download your service account key from Firebase Console
// and either set it as an environment variable or place it in the project
let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  // Use environment variable for service account
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
  // Use local service account file (for development)
  try {
    serviceAccount = require('./firebase-service-account.json');
  } catch (error) {
    console.warn('Firebase service account not found. Firebase Admin SDK will not be initialized.');
    return;
  }
}

if (serviceAccount) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL || `https://${serviceAccount.project_id}.firebaseio.com`
  });
}

// Export Firebase services
const db = admin.firestore();
const auth = admin.auth();

module.exports = {
  admin,
  db,
  auth
}; 