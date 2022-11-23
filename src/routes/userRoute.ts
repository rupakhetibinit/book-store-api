import express, { Request, Response } from 'express';
import validate from '../middlewares/validate';
import z from 'zod';
import prisma from '../prisma';
import argon2 from 'argon2';
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
	async (req: Request<{}, {}, Schema>, res: Response) => {
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
				},
			});
			return res.status(201).json(user);
		} catch (error) {
			return res.status(400).json({ error: error });
		}
	}
);

router.post(
	'/login',
	validate(z.object({ body })),
	async (req: Request<{}, {}, Schema>, res) => {
		const user = await prisma.user.findUnique({
			where: {
				email: req.body.email,
			},
		});
		if (!user)
			return res.status(400).json({
				error: {
					message: "Credentials don't match",
				},
			});

		const verified = await argon2.verify(user.password, req.body.password);

		if (!verified)
			return res.status(400).json({
				error: {
					message: "Credentials don't match",
				},
			});

		return res.json({ name: user.name, email: user.email });
	}
);
export default router;
