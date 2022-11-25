import prisma from '../prisma';
import { NextFunction, Request, Response } from 'express';
const auth = async (req: Request, res: Response, next: NextFunction) => {
	try {
		const session_id = req.cookies.session_id;
		if (!session_id) {
			return res.status(401).json({
				data: null,
				error: { message: 'You are not authenticated' },
			});
		}

		const session = await prisma.session.findUnique({
			where: {
				id: session_id,
			},
		});

		if (!session) {
			res.clearCookie('session_id');
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
