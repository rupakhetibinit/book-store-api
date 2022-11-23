import express, { Request, Response } from 'express';
import userRoute from './routes/userRoute';
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.use('/api/auth', userRoute);

const start = () => {
	try {
		app.listen(port, () => {
			console.log(`Express server started on port ${port}`);
		});
	} catch (error) {
		console.error(error);
		process.exit(1);
	}
};

start();
