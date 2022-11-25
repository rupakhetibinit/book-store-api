import express, { NextFunction, Request, Response } from 'express';
import config from '../config/config';
import validate from '../middlewares/validate';
import z, { string } from 'zod';
import prisma from '../prisma';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { nextTick } from 'process';
import { User } from '@prisma/client';
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

			const accessToken = jwt.sign(user, config.jwtAccessSecret, {
				expiresIn: 300,
			});
			const refreshToken = jwt.sign(user, config.jwtRefreshSecret, {
				expiresIn: '5d',
			});

			return res
				.status(201)
				.json({ data: { accessToken, refreshToken }, error: null });
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
			const jwtUser = { id: user.id, email: user.email, name: user.name };
			if (!verified)
				return res.status(400).json({
					error: {
						message: "Credentials don't match",
					},
				});
			const accessToken = jwt.sign(jwtUser, config.jwtAccessSecret, {
				expiresIn: 10,
			});
			const refreshToken = jwt.sign(jwtUser, config.jwtRefreshSecret, {
				expiresIn: '5d',
			});

			return res.json({
				data: {
					accessToken,
					refreshToken,
					id: user.id,
					name: user.name,
					email: user.email,
				},
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

router.post('/me', async (req: Request, res: Response, next: NextFunction) => {
	try {
		const refreshToken = req.headers.authorization?.split(' ')[1];
		if (!refreshToken) {
			return res.status(401).json({
				data: null,
				error: { message: 'No token' },
			});
		}

		const verify = jwt.verify(refreshToken, config.jwtRefreshSecret);
		//@ts-ignore
		const decoded = jwt.decode(refreshToken);

		console.log(`decoded ${JSON.stringify(decoded)}`);

		if (!verify) {
			return res.status(401).json({
				data: null,
				error: { message: 'Please Login Again' },
			});
		}
		//@ts-ignore
		const newAccessToken = jwt.sign(
			//@ts-ignore
			{ id: decoded.id, email: decoded.email, name: decoded.name },
			config.jwtAccessSecret,
			{
				expiresIn: 300,
			}
		);
		const newRefreshToken = jwt.sign(
			{
				//@ts-ignore
				id: decoded.id,
				//@ts-ignore
				email: decoded.email,
				//@ts-ignore
				name: decoded.name,
			},
			config.jwtRefreshSecret,
			{
				expiresIn: '5d',
			}
		);
		return res.json({
			data: {
				accessToken: newAccessToken,
				refreshToken: newRefreshToken,
			},
			error: null,
		});
	} catch (error) {
		next(error);
	}
});
export default router;
