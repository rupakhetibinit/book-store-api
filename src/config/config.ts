const envConfig = {
	jwtAccessSecret: process.env.JWT_ACCESS_SECRET || 'whateverfornow',
	jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'thisismysecret',
};

export default envConfig;
