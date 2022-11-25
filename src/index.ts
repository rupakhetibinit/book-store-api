import express, {
	ErrorRequestHandler,
	NextFunction,
	Request,
	Response,
} from 'express';
import userRoute from './routes/userRoute';
import bookRoute from './routes/bookRoute';
const app = express();
const port = process.env.PORT || 3000;

const errorLogger = (
	error: Error,
	_request: Request,
	_response: Response,
	next: NextFunction
) => {
	console.log(error);
	console.log(`error ${error.message}`);
	next(error); // calling next middleware
};

// Error handling Middleware function reads the error message
// and sends back a response in JSON format
const errorResponder = (
	error: any,
	_request: Request,
	response: Response,
	_next: NextFunction
) => {
	response.header('Content-Type', 'application/json');

	const status = error.status || 400;
	response.status(status).send({ data: null, error });
};

app.use(express.json());

app.use('/api/auth', userRoute);
app.use('/', bookRoute);

// Error handling
app.use(errorLogger);
app.use(errorResponder);

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
