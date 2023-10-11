const functions = require('firebase-functions/v2');
const admin = require('firebase-admin');
require('firebase-functions/logger/compat');

admin.initializeApp();

// DELETE https://us-central1-<project-id>.cloudfunctions.net/deleteUserAccount
exports.deleteUserAccount = functions.https.onRequest(
  { cors: true, maxInstances: 10 },
  async (req, res) => {
    try {
      // Lấy authToken từ header của request
      const authToken = req.header('Authorization')?.split('Bearer ')[1];

      if (!authToken) {
        res.status(401).send('Authentication token missing.');
        return;
      }

      // Xác thực mã thông báo xác thực (authToken)
      const decodedToken = await admin.auth().verifyIdToken(authToken);

      // Người dùng đã xác thực thành công
      const uid = decodedToken.uid;

      const isAdmin = await admin
        .firestore()
        .collection('users')
        .doc(uid)
        .get()
        .then((doc) => doc.data().admin);

      if (!isAdmin) {
        res.status(403).send('Permission denied.');
        return;
      }

      // Lấy UID từ body của request
      const uidToDelete = req.body.uid;

      // Kiểm tra xem UID có tồn tại không
      if (!uidToDelete) {
        res.status(400).send('UID is required.');
        return;
      }

      // Kiểm tra xem UID có tồn tại trong hệ thống không
      const user = await admin.auth().getUser(uidToDelete);
      if (!user) {
        res.status(400).send('User does not exist.');
        return;
      }

      // Kiểm tra xem người dùng đang cố gắng xóa tài khoản của chính mình
      if (uid === uidToDelete) {
        res.status(400).send('Cannot delete your own account.');
        return;
      }

      // Sử dụng Firebase Admin SDK để xóa tài khoản người dùng
      await admin.auth().deleteUser(uidToDelete);
      await admin.firestore().collection('users').doc(uidToDelete).delete();
      await admin.storage().bucket().deleteFiles({
        prefix: uidToDelete,
      });

      // Trả về kết quả thành công
      res.status(200).send('User account deleted successfully.');
    } catch (error) {
      console.error('Error deleting user:', error);
      res.status(500).send('Error deleting user account.');
    }
  }
);
