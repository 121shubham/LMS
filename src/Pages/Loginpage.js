import React, { useState } from 'react';
import { TextField, Button,Container, Typography,InputLabel, Box, Alert,MenuItem,Select,FormControl,FormHelperText } from '@mui/material';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
  },
});



export default function RegisterForm() {
  const navigate=useNavigate();
  const [form, setForm] = useState({ email: '', username: '', password: '',role:'',mobile:'' });
  const [error, setError] = useState(''); 
  const [success, setSuccess] = useState('');
  const [fieldErrors, setFieldErrors] = useState({});

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };


  
  const validate = () => {
    const errors = {};
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const mobileRegex = /^[0-9]{10}$/;

    if (!form.email) errors.email = 'Email is required';
    else if (!emailRegex.test(form.email)) errors.email = 'Invalid email format';

    if (!form.username) errors.username = 'Username is required';
    if (!form.password) errors.password = 'Password is required';
    else if (form.password.length < 6) errors.password = 'Password must be at least 6 characters';

    if (!form.mobile) errors.mobile = 'Mobile number is required';
    else if (!mobileRegex.test(form.mobile)) errors.mobile = 'Mobile must be 10 digits';

    if (!form.role) errors.role = 'Role is required';

    setFieldErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

  if(!validate()) return;

    try {
      await axios.post('http://localhost:8000/api/lms_app/signup/', form);
      setSuccess("Success");
      setForm({ email: '', username: '', password: '',role:'', mobile:'' });
      setTimeout(()=>{
        navigate('/Userlogin')
      }, 2000);
    } catch (err) {
      const errorMsg = err.response?.data || 'Something went wrong.';
      setError(JSON.stringify(errorMsg));
    }
  };


  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline>
    <Container>
    <Box sx={{ maxWidth: 400, margin: 'auto', mt: 8, }}>
      <Typography variant="h4" gutterBottom>Register</Typography>
      {error && <Alert severity="error">{error}</Alert>}
      {success && <Alert severity="success">{success}</Alert>}
      <form onSubmit={handleSubmit}>
        <TextField label="Email" name="email" fullWidth margin="normal" value={form.email} onChange={handleChange} required  error={!!fieldErrors.email} helperText={fieldErrors.email} />
        <TextField label="Username" name="username" fullWidth margin="normal" value={form.username} onChange={handleChange} required  error={!!fieldErrors.username} helperText={fieldErrors.username} />
        <TextField label="Mobile" name="mobile" fullWidth margin="normal" value={form.mobile} onChange={handleChange} required  error={!!fieldErrors.mobile} helperText={fieldErrors.mobile} />
        <TextField label="Password"
         name="password" 
         type="password"
         fullWidth
         margin="normal" 
         value={form.password} 
         onChange={handleChange}
         required 
          error={!!fieldErrors.password} helperText={fieldErrors.password}
           />
    <FormControl fullWidth margin="normal" error={!!fieldErrors.role}>
    <InputLabel id="role-label">User Role</InputLabel>
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
        <Button variant="contained" color="primary" type="submit" fullWidth sx={{ mt: 2 }}>Register</Button>
      </form>
    </Box>
  </Container>
  </CssBaseline>
  </ThemeProvider>
  );
}
