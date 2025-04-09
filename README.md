# Endpoint Management System

A web application for collecting and displaying workstation details in a local network.

## Features

- Collect endpoint information using Python scripts
- Store data in MySQL database
- RESTful API for data access
- Angular frontend for data visualization
- Dashboard with statistics and charts
- Detailed endpoint information view
- Software inventory management

## Project Structure

- `backend/`: Flask API server
- `src/`: Angular frontend application

## Setup Instructions

### Prerequisites

- Python 3.8+
- Node.js 14+
- MySQL Server

### Backend Setup

1. Create a MySQL database:

```sql
CREATE DATABASE endpoint_management;
```

2. Install Python dependencies:

```bash
cd backend
pip install -r requirements.txt
```

3. Configure the database connection in `backend/app.py`:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/endpoint_management'
```

4. Run the Flask server:

```bash
python app.py
```

### Frontend Setup

1. Install Angular dependencies:

```bash
npm install
```

2. Run the Angular development server:

```bash
npm start
```

## Deployment

### Local Deployment

1. Build the Angular application:

```bash
npm run build
```

2. Run the Flask application:

```bash
python backend/app.py
```

3. Access the application at http://localhost:5000

## API Endpoints

- `GET /api/endpoints`: Get all endpoints
- `GET /api/endpoints/{id}`: Get endpoint by ID
- `GET /api/endpoints/{ip_address}/latest`: Get latest endpoint data by IP
- `GET /api/endpoints/{id}/software`: Get software for an endpoint
- `POST /api/endpoints`: Add new endpoint data
- `GET /api/stats`: Get system statistics
- `GET /api/health`: Health check endpoint

## Data Collection

Use the provided Python scripts to collect endpoint data:

1. Run the collection script on a Windows machine:

```bash
python endpoint_collection.py --ip 192.168.1.100,192.168.1.101 --user domain\\username
```

2. Push the collected data to the API:

```bash
python data_pusher.py --basic endpoint_details.csv --software endpoint_details_software.csv
```
