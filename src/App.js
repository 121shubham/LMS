import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Loginpage from './Pages/Loginpage';
import { GoogleOAuthProvider } from '@react-oauth/google';
import AdminDashboard from './Pages/AdminDashboard';
import FacultyPanel from './Pages/FacultyPanel';
import StudentHome from './Pages/StudentHome';
import Userlogin from './Pages/Userlogin';

const App = () => {
  return (
    <GoogleOAuthProvider clientId="947016098473-oes2psie4hcs95ibovbhihhb801dj4mm.apps.googleusercontent.com">
      <Router>
        <Routes>
          <Route path='/' element={<Loginpage />} />
          <Route path="/Userlogin" element={<Userlogin />} />
          <Route path='/admindashboard' element={<AdminDashboard />} />
          <Route path='/facultydashboard' element={<FacultyPanel />} />
          <Route path='/studentdashboard' element={<StudentHome />} />
        </Routes>
      </Router>

     </GoogleOAuthProvider>
  );
};

export default App;
