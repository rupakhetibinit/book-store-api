import express from 'express';
import auth from '../middlewares/auth';

const router = express.Router();

router.post('/book', auth, (req, res) => {
	res.json({ data: 'You are an authenticated user', error: null });
});

export default router;
