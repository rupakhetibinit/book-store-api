import express, { NextFunction, Request, Response } from 'express';
import config from '../config/config';
import validate from '../middlewares/validate';
import z, { string } from 'zod';
import prisma from '../prisma';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { nextTick } from 'process';
import { User } from '@prisma/client';
import { v4 as uuidv4 } from 'uuid';
const router = express.Router();

const body = z.object({
	email: z
		.string({ required_error: 'Email is required' })
		.email('Invalid Email provided'),
	password: z
		.string({ required_error: 'Password is required' })
		.min(6, 'Must have 6 characters in password'),
	name: z.string().optional(),
});

type Schema = z.infer<typeof body>;

router.post(
	'/signup',
	validate(z.object({ body })),
	async (req: Request<{}, {}, Schema>, res: Response, next: NextFunction) => {
		try {
			const foundUser = await prisma.user.findUnique({
				where: {
					email: req.body.email,
				},
			});
			if (foundUser)
				return res.status(400).json({
					error: {
						message: 'Email is already used',
					},
				});
			const hashedPassword = await argon2.hash(req.body.password);

			const user = await prisma.user.create({
				data: {
					email: req.body.email,
					password: hashedPassword,
					name: req.body.name,
				},
				select: {
					email: true,
					name: true,
					id: true,
				},
			});

			// const accessToken = jwt.sign(user, config.jwtAccessSecret, {
			// 	expiresIn: 300,
			// });
			// const refreshToken = jwt.sign(user, config.jwtRefreshSecret, {
			// 	expiresIn: '5d',
			// });
			const session_id = uuidv4();
			await prisma.session.create({
				data: {
					id: session_id,
					userId: user.id,
				},
			});
			res.cookie('session_id', session_id, {
				maxAge: 30 * 24 * 60 * 60 * 1000,
				path: '/',
				secure: false,
			});
			return res.status(201).json({ data: user, error: null });
		} catch (error) {
			next(error);
		}
	}
);

router.post(
	'/login',
	validate(z.object({ body })),
	async (req: Request<{}, {}, Schema>, res, next) => {
		try {
			const user = await prisma.user.findUnique({
				where: {
					email: req.body.email,
				},
			});
			if (!user)
				return res.status(400).json({
					data: null,
					error: {
						message: "Credentials don't match",
					},
				});

			const verified = await argon2.verify(user.password, req.body.password);
			// const jwtUser = { id: user.id, email: user.email, name: user.name };
			if (!verified)
				return res.status(400).json({
					error: {
						message: "Credentials don't match",
					},
				});
			// const accessToken = jwt.sign(jwtUser, config.jwtAccessSecret, {
			// 	expiresIn: 100,
			// });
			// const refreshToken = jwt.sign(jwtUser, config.jwtRefreshSecret, {
			// 	expiresIn: '5d',
			// });
			const session_id = uuidv4();
			await prisma.session.create({
				data: {
					id: session_id,
					userId: user.id,
				},
			});
			res.cookie('session_id', session_id, {
				maxAge: 30 * 24 * 60 * 60 * 1000,
				path: '/',
				secure: false,
				httpOnly: true,
			});
			const finalUser = { id: user.id, email: user.email, name: user.name };
			return res.json({
				data: finalUser,
				error: null,
			});
		} catch (error) {
			next(error);
		}
	}
);

interface DecodedUser {
	name: string;
	email: string;
	id: string;
}
type UserType = DecodedUser | null;

// router.post('/me', async (req: Request, res: Response, next: NextFunction) => {
// 	try {
// 		const refreshToken = req.headers.authorization?.split(' ')[1];
// 		if (!refreshToken) {
// 			return res.status(401).json({
// 				data: null,
// 				error: { message: 'No token' },
// 			});
// 		}

// 		const verify = jwt.verify(refreshToken, config.jwtRefreshSecret);
// 		//@ts-ignore
// 		const decoded = jwt.decode(refreshToken);

// 		console.log(`decoded ${JSON.stringify(decoded)}`);

// 		if (!verify) {
// 			return res.status(401).json({
// 				data: null,
// 				error: { message: 'Please Login Again' },
// 			});
// 		}
// 		//@ts-ignore
// 		const newAccessToken = jwt.sign(
// 			//@ts-ignore
// 			{ id: decoded.id, email: decoded.email, name: decoded.name },
// 			config.jwtAccessSecret,
// 			{
// 				expiresIn: 300,
// 			}
// 		);
// 		const newRefreshToken = jwt.sign(
// 			{
// 				//@ts-ignore
// 				id: decoded.id,
// 				//@ts-ignore
// 				email: decoded.email,
// 				//@ts-ignore
// 				name: decoded.name,
// 			},
// 			config.jwtRefreshSecret,
// 			{
// 				expiresIn: '5d',
// 			}
// 		);
// 		res.cookie('access_token', newAccessToken, {
// 			maxAge: 3000,
// 			httpOnly: false,
// 			path: '/',
// 		});
// 		return res.json({
// 			data: {
// 				accessToken: newAccessToken,
// 				refreshToken: newRefreshToken,
// 			},
// 			error: null,
// 		});
// 	} catch (error) {
// 		next(error);
// 	}
// });

router.post('/logoutall', async (req, res, next) => {
	try {
		const session_id = req.cookies.session_id;
		const session = await prisma.session.findUniqueOrThrow({
			where: {
				id: session_id,
			},
			select: {
				user: {
					select: {
						id: true,
					},
				},
			},
		});

		await prisma.session.deleteMany({
			where: {
				userId: session.user.id,
			},
		});

		res.clearCookie('session_id');
		return res.json({
			data: { message: 'logout on all sessions' },
			error: null,
		});
	} catch (error) {
		next(error);
	}
});

router.post('/logout', async (req, res, next) => {
	try {
		const session_id = req.cookies.session_id;
		await prisma.session.delete({
			where: {
				id: session_id,
			},
		});

		res.clearCookie('session_id');
		return res.json({
			data: { message: 'logout on this session' },
			error: null,
		});
	} catch (error) {
		next(error);
	}
});

export default router;
