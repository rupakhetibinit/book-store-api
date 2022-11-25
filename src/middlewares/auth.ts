import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import config from '../config/config';
const auth = async (req: Request, res: Response, next: NextFunction) => {
	try {
		const accessToken = req.headers.authorization?.split(' ')[1];
		if (!accessToken) {
			return res.status(401).json({
				data: null,
				error: { message: 'You are not authenticated' },
			});
		}

		const verify = jwt.verify(accessToken, config.jwtAccessSecret);

		if (!verify) {
			return res.status(401).json({
				data: null,
				error: { message: 'You are not authenticated' },
			});
		}

		next();
	} catch (error) {
		next(error);
	}
};

export default auth;
