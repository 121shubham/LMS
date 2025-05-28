import React, { useState } from 'react';
import {
  Container,
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  Select,
  MenuItem,
  FormControl,FormHelperText,
  InputLabel
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

export default function Userlogin() {

//   const [username, setUsername] = useState('');
//   const [password, setPassword] = useState('');
  const [form, setForm] = useState({username:'',password:'',role:''});
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate=useNavigate();
  const [fieldErrors, setFieldErrors] = useState({});

  const handleChange=(e) =>{
    setForm({...form,[e.target.name]: e.target.value});

  };

  const validate=()=>{
    const errors={};

    if (!form.username) errors.username = 'Username is required';
    if (!form.password) errors.password = 'Password is required';
    else if (form.password.length < 6) errors.password = 'Password must be at least 6 characters';


    if (!form.role) errors.role = 'Role is required';

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;


  }

  const handleSubmit = async (e) => {
  e.preventDefault();
  setError('');
  setSuccess('');

  if (!validate()) return;

  try {
    const response = await axios.post('http://localhost:8000/api/lms_app/login/', form);
    

    const { role, username } = response.data;
    setSuccess(`Login Successful! Welcome ${username}`);

    setTimeout(() => {
      if (role === 'admin') {
        navigate('/admindashboard');
      } else if (role === 'faculty') {
        navigate('/facultydashboard');
      } else {
        navigate('/student');
      }
    }, 1500);

  } catch (err) {
    const errorMsg = err.response?.data?.error || "Login failed. Please check your credentials.";
    setError(errorMsg);

    setTimeout(() => {
      navigate('/');
    }, 5000);
  }
};


  return (
    <Container>
      <Box sx={{ maxWidth: 400, mx: 'auto', mt: 8 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Typography variant="h5" gutterBottom>
            User Login
          </Typography>
          {error && (
            <Alert severity="error" sx={{
            backgroundColor: '#ffebee', // light red background
            color: '#b71c1c',            // dark red text
            border: '1px solid #f44336',
            borderRadius: 2,
            fontWeight: 500,
    }}>
              {error}. Don't have an account? <a href="/">Create one</a>.
            </Alert>
          )}
          <form onSubmit={handleSubmit}>
            <TextField
              label="Username"
              name='username'
              fullWidth
              margin="normal"
              value={form.username}
              onChange={handleChange}
              error={!!fieldErrors.username} 
              helperText={fieldErrors.username}
              required
            />
            <TextField
              label="Password"
              name='password'
              type="password"
              fullWidth
              margin="normal"
              value={form.password}
              onChange={handleChange}
              error={!!fieldErrors.password}
              helperText={fieldErrors.password}
              required
            />
            <FormControl fullWidth margin="normal" error={!!fieldErrors.role}>
            
            <InputLabel id="role-label">User role</InputLabel>
            <Select
            labelId="role-label"
            id="role"
            name="role"
            fullWidth
            value={form.role}
            label="User Role"
            onChange={handleChange}
            required
            >
            <MenuItem value="admin">Admin</MenuItem>
            <MenuItem value="student">Student</MenuItem>
            <MenuItem value="faculty">Faculty</MenuItem>
            </Select>
            {fieldErrors.role && <FormHelperText>{fieldErrors.role}</FormHelperText>}
            
            </FormControl>
            <Button type="submit" variant="contained" color="primary" fullWidth sx={{ mt: 2 }}>
              Login
            </Button>

            <p> Don't have account ? Click here to  <a href='/'>Signin</a></p>
          </form>
        </Paper>
      </Box>
    </Container>
  );
}
