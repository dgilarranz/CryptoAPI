FROM ruby:3.4.1

# Install application under /usr/src/app
WORKDIR /usr/src/app

# Fail if .env file is not present
COPY .env .

# Fail unless .env file contains the API key
RUN grep -qE '^API_KEY=.+$' .env || ( echo '.env file must provide an API_KEY. Exiting.' && exit 1 )

# Copy Gemfile and install dependencies
COPY Gemfile ./
RUN bundle config set without 'development test'
RUN bundle install

# Copy application source code
COPY config.ru .
ADD lib ./lib
ADD public ./public

CMD ["bundle", "exec", "puma", "-e", "production", "-p", "8000"]
