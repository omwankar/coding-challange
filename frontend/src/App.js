import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import axios from 'axios';
import './App.css';

// Components
import { Button } from './components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './components/ui/card';
import { Input } from './components/ui/input';
import { Label } from './components/ui/label';
import { Badge } from './components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { AlertCircle, Star, Users, Store, TrendingUp, Search, Filter, Eye, EyeOff, LogOut, Plus, Check, X, Mail, MapPin, User } from 'lucide-react';
import { toast, Toaster } from 'sonner';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from './components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select';
import { Textarea } from './components/ui/textarea';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Auth Context
const AuthContext = createContext();

const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const storedToken = localStorage.getItem('token');
    const storedUser = localStorage.getItem('user');
    
    if (storedToken && storedUser) {
      try {
        const userData = JSON.parse(storedUser);
        setUser(userData);
        setToken(storedToken);
        axios.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`;
      } catch (error) {
        console.error('Error parsing stored user data:', error);
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      }
    }
    setLoading(false);
  }, []);

  const login = (userData, authToken) => {
    setUser(userData);
    setToken(authToken);
    localStorage.setItem('token', authToken);
    localStorage.setItem('user', JSON.stringify(userData));
    axios.defaults.headers.common['Authorization'] = `Bearer ${authToken}`;
    
    // Redirect based on user role
    setTimeout(() => {
      if (userData.role === 'system_admin') {
        window.location.href = '/admin';
      } else if (userData.role === 'normal_user') {
        window.location.href = '/dashboard';
      } else if (userData.role === 'store_owner') {
        window.location.href = '/store-dashboard';
      }
    }, 100);
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    delete axios.defaults.headers.common['Authorization'];
    window.location.href = '/login';
    toast.success('Logged out successfully');
  };

  const value = {
    user,
    token,
    login,
    logout,
    loading
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Login Component
const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await axios.post(`${API}/auth/login`, {
        email,
        password
      });

      login(response.data.user, response.data.access_token);
      toast.success('Login successful!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
    }

    setLoading(false);
  };

  // Quick admin login for demo
  const handleAdminLogin = () => {
    setEmail('admin@storerate.com');
    setPassword('AdminPass123!');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-sky-50 to-indigo-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-2xl border-0 bg-white/90 backdrop-blur-sm">
        <CardHeader className="text-center">
          <CardTitle className="text-3xl font-bold text-gray-800">Store Rating System</CardTitle>
          <CardDescription className="text-gray-600">Login to your account</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium">Email</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email"
                required
                data-testid="login-email"
                className="h-12"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  data-testid="login-password"
                  className="h-12 pr-12"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2 top-2 h-8 w-8 p-0"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </Button>
              </div>
            </div>
            <Button 
              type="submit" 
              className="w-full h-12 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-semibold rounded-lg transition-all duration-200"
              disabled={loading}
              data-testid="login-submit"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
          
          <div className="mt-6 space-y-3">
            <div className="text-center">
              <span className="text-sm text-gray-500">Demo Account:</span>
            </div>
            <Button
              variant="outline"
              onClick={handleAdminLogin}
              className="w-full border-blue-200 text-blue-600 hover:bg-blue-50"
              data-testid="demo-admin-login"
            >
              Login as Admin
            </Button>
          </div>

          <div className="mt-6 text-center space-y-2">
            <p className="text-sm text-gray-600">
              Don't have an account?{' '}
              <Button variant="link" className="p-0 text-blue-600 font-semibold" onClick={() => window.location.href = '/register'}>
                Sign up here
              </Button>
            </p>
            <p className="text-sm text-gray-600">
              Want to register your store?{' '}
              <Button variant="link" className="p-0 text-orange-600 font-semibold" onClick={() => window.location.href = '/store-register'}>
                Store Registration
              </Button>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Store Owner Registration Component
const StoreOwnerRegister = () => {
  const [formData, setFormData] = useState({
    user: {
      name: '',
      email: '',
      address: '',
      password: '',
      confirmPassword: ''
    },
    store: {
      name: '',
      email: '',
      address: ''
    }
  });
  const [loading, setLoading] = useState(false);

  const handleUserChange = (e) => {
    setFormData({
      ...formData,
      user: {
        ...formData.user,
        [e.target.name]: e.target.value
      }
    });
  };

  const handleStoreChange = (e) => {
    setFormData({
      ...formData,
      store: {
        ...formData.store,
        [e.target.name]: e.target.value
      }
    });
  };

  const validateForm = () => {
    if (formData.user.name.length < 20 || formData.user.name.length > 60) {
      toast.error('Name must be between 20 and 60 characters');
      return false;
    }
    if (formData.user.address.length > 400) {
      toast.error('User address must be less than 400 characters');
      return false;
    }
    if (formData.store.address.length > 400) {
      toast.error('Store address must be less than 400 characters');
      return false;
    }
    if (formData.user.password !== formData.user.confirmPassword) {
      toast.error('Passwords do not match');
      return false;
    }
    if (!/^(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?])/.test(formData.user.password)) {
      toast.error('Password must contain at least one uppercase letter and one special character');
      return false;
    }
    return true;
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    setLoading(true);

    try {
      const response = await axios.post(`${API}/auth/store-owner-register`, {
        user: {
          name: formData.user.name,
          email: formData.user.email,
          address: formData.user.address,
          password: formData.user.password
        },
        store: {
          name: formData.store.name,
          email: formData.store.email,
          address: formData.store.address
        }
      });

      toast.success('Store owner registration submitted for admin approval!');
      
      // Redirect to login after successful registration
      setTimeout(() => {
        window.location.href = '/login';
      }, 2000);
      
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Registration failed');
    }

    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-orange-50 to-red-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl shadow-2xl border-0 bg-white/90 backdrop-blur-sm">
        <CardHeader className="text-center">
          <CardTitle className="text-3xl font-bold text-gray-800">Register Your Store</CardTitle>
          <CardDescription className="text-gray-600">Join our platform as a store owner (Admin approval required)</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleRegister} className="space-y-6">
            <div className="border rounded-lg p-4 bg-blue-50">
              <h3 className="font-semibold mb-4 text-blue-800">Owner Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="user-name">Full Name (20-60 characters)</Label>
                  <Input
                    id="user-name"
                    name="name"
                    value={formData.user.name}
                    onChange={handleUserChange}
                    placeholder="Enter your full name"
                    required
                    data-testid="store-owner-name"
                    className="h-12"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="user-email">Email Address</Label>
                  <Input
                    id="user-email"
                    name="email"
                    type="email"
                    value={formData.user.email}
                    onChange={handleUserChange}
                    placeholder="Enter your email"
                    required
                    data-testid="store-owner-email"
                    className="h-12"
                  />
                </div>
              </div>
              <div className="space-y-2 mt-4">
                <Label htmlFor="user-address">Personal Address (Max 400 characters)</Label>
                <Textarea
                  id="user-address"
                  name="address"
                  value={formData.user.address}
                  onChange={handleUserChange}
                  placeholder="Enter your personal address"
                  required
                  data-testid="store-owner-address"
                  className="min-h-20"
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                <div className="space-y-2">
                  <Label htmlFor="user-password">Password (8-16 chars, 1 uppercase, 1 special)</Label>
                  <Input
                    id="user-password"
                    name="password"
                    type="password"
                    value={formData.user.password}
                    onChange={handleUserChange}
                    placeholder="Enter your password"
                    required
                    data-testid="store-owner-password"
                    className="h-12"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="user-confirm-password">Confirm Password</Label>
                  <Input
                    id="user-confirm-password"
                    name="confirmPassword"
                    type="password"
                    value={formData.user.confirmPassword}
                    onChange={handleUserChange}
                    placeholder="Confirm your password"
                    required
                    data-testid="store-owner-confirm-password"
                    className="h-12"
                  />
                </div>
              </div>
            </div>

            <div className="border rounded-lg p-4 bg-green-50">
              <h3 className="font-semibold mb-4 text-green-800">Store Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="store-name">Store Name</Label>
                  <Input
                    id="store-name"
                    name="name"
                    value={formData.store.name}
                    onChange={handleStoreChange}
                    placeholder="Enter your store name"
                    required
                    data-testid="store-name"
                    className="h-12"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="store-email">Store Email</Label>
                  <Input
                    id="store-email"
                    name="email"
                    type="email"
                    value={formData.store.email}
                    onChange={handleStoreChange}
                    placeholder="Enter store email"
                    required
                    data-testid="store-email"
                    className="h-12"
                  />
                </div>
              </div>
              <div className="space-y-2 mt-4">
                <Label htmlFor="store-address">Store Address (Max 400 characters)</Label>
                <Textarea
                  id="store-address"
                  name="address"
                  value={formData.store.address}
                  onChange={handleStoreChange}
                  placeholder="Enter store address"
                  required
                  data-testid="store-address"
                  className="min-h-20"
                />
              </div>
            </div>

            <Button 
              type="submit" 
              className="w-full h-12 bg-gradient-to-r from-orange-600 to-red-600 hover:from-orange-700 hover:to-red-700 text-white font-semibold rounded-lg transition-all duration-200"
              disabled={loading}
              data-testid="store-owner-submit"
            >
              {loading ? 'Submitting for Approval...' : 'Register Store'}
            </Button>
          </form>
          
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              Already have an account?{' '}
              <Button variant="link" className="p-0 text-orange-600 font-semibold" onClick={() => window.location.href = '/login'}>
                Sign in here
              </Button>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    address: '',
    password: '',
    confirmPassword: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const validateForm = () => {
    if (formData.name.length < 20 || formData.name.length > 60) {
      toast.error('Name must be between 20 and 60 characters');
      return false;
    }
    if (formData.address.length > 400) {
      toast.error('Address must be less than 400 characters');
      return false;
    }
    if (formData.password !== formData.confirmPassword) {
      toast.error('Passwords do not match');
      return false;
    }
    if (!/^(?=.*[A-Z])(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?])/.test(formData.password)) {
      toast.error('Password must contain at least one uppercase letter and one special character');
      return false;
    }
    return true;
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    setLoading(true);

    try {
      const response = await axios.post(`${API}/auth/register`, {
        name: formData.name,
        email: formData.email,
        address: formData.address,
        password: formData.password
      });

      login(response.data.user, response.data.access_token);
      toast.success('Registration successful!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Registration failed');
    }

    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-100 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-2xl border-0 bg-white/90 backdrop-blur-sm">
        <CardHeader className="text-center">
          <CardTitle className="text-3xl font-bold text-gray-800">Join Our Platform</CardTitle>
          <CardDescription className="text-gray-600">Create your account to start rating stores</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleRegister} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Full Name (20-60 characters)</Label>
              <Input
                id="name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                placeholder="Enter your full name"
                required
                data-testid="register-name"
                className="h-12"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email Address</Label>
              <Input
                id="email"
                name="email"
                type="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="Enter your email"
                required
                data-testid="register-email"
                className="h-12"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="address">Address (Max 400 characters)</Label>
              <Textarea
                id="address"
                name="address"
                value={formData.address}
                onChange={handleChange}
                placeholder="Enter your address"
                required
                data-testid="register-address"
                className="min-h-20"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password (8-16 chars, 1 uppercase, 1 special)</Label>
              <div className="relative">
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Enter your password"
                  required
                  data-testid="register-password"
                  className="h-12 pr-12"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2 top-2 h-8 w-8 p-0"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                name="confirmPassword"
                type="password"
                value={formData.confirmPassword}
                onChange={handleChange}
                placeholder="Confirm your password"
                required
                data-testid="register-confirm-password"
                className="h-12"
              />
            </div>
            <Button 
              type="submit" 
              className="w-full h-12 bg-gradient-to-r from-green-600 to-blue-600 hover:from-green-700 hover:to-blue-700 text-white font-semibold rounded-lg transition-all duration-200"
              disabled={loading}
              data-testid="register-submit"
            >
              {loading ? 'Creating Account...' : 'Create Account'}
            </Button>
          </form>
          
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              Already have an account?{' '}
              <Button variant="link" className="p-0 text-blue-600 font-semibold" onClick={() => window.location.href = '/login'}>
                Sign in here
              </Button>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

// Admin Dashboard Components
const AdminDashboard = () => {
  const [stats, setStats] = useState({ total_users: 0, total_stores: 0, total_ratings: 0 });
  const [users, setUsers] = useState([]);
  const [stores, setStores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [showAddUserDialog, setShowAddUserDialog] = useState(false);
  const [showAddStoreDialog, setShowAddStoreDialog] = useState(false);
  const [selectedUserDetails, setSelectedUserDetails] = useState(null);
  
  // Filter states
  const [userFilters, setUserFilters] = useState({
    name: '',
    email: '',
    address: '',
    role: ''
  });
  const [storeFilters, setStoreFilters] = useState({
    name: '',
    email: '',
    address: ''
  });

  // Add User Form
  const [addUserForm, setAddUserForm] = useState({
    name: '',
    email: '',
    password: '',
    address: '',
    role: 'normal_user'
  });

  // Add Store Form  
  const [addStoreForm, setAddStoreForm] = useState({
    name: '',
    email: '',
    address: '',
    owner_email: ''
  });

  useEffect(() => {
    fetchDashboardData();
  }, [userFilters, storeFilters]);

  const fetchDashboardData = async () => {
    try {
      const statsRes = await axios.get(`${API}/admin/dashboard`);
      
      // Build query params for users
      const userParams = new URLSearchParams();
      Object.entries(userFilters).forEach(([key, value]) => {
        if (value) userParams.append(key, value);
      });
      
      // Build query params for stores  
      const storeParams = new URLSearchParams();
      Object.entries(storeFilters).forEach(([key, value]) => {
        if (value) storeParams.append(key, value);
      });

      const [usersRes, storesRes] = await Promise.all([
        axios.get(`${API}/admin/users?${userParams}`),
        axios.get(`${API}/admin/stores?${storeParams}`)
      ]);

      setStats(statsRes.data);
      setUsers(usersRes.data);
      setStores(storesRes.data);
    } catch (error) {
      toast.error('Failed to fetch dashboard data');
    }
    setLoading(false);
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${API}/admin/users?role=${addUserForm.role}`, {
        name: addUserForm.name,
        email: addUserForm.email,
        password: addUserForm.password,
        address: addUserForm.address
      });
      
      toast.success('User added successfully');
      setShowAddUserDialog(false);
      setAddUserForm({ name: '', email: '', password: '', address: '', role: 'normal_user' });
      fetchDashboardData();
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to add user');
    }
  };

  const approveStore = async (storeId) => {
    try {
      await axios.put(`${API}/admin/stores/${storeId}/approve`);
      toast.success('Store approved successfully');
      fetchDashboardData();
    } catch (error) {
      toast.error('Failed to approve store');
    }
  };

  const rejectStore = async (storeId) => {
    try {
      await axios.put(`${API}/admin/stores/${storeId}/reject`);
      toast.success('Store rejected');
      fetchDashboardData();
    } catch (error) {
      toast.error('Failed to reject store');
    }
  };

  const getStatusBadge = (status) => {
    const variants = {
      'pending': 'bg-yellow-100 text-yellow-800',
      'approved': 'bg-green-100 text-green-800',
      'rejected': 'bg-red-100 text-red-800'
    };
    return (
      <Badge className={variants[status] || 'bg-gray-100 text-gray-800'}>
        {status?.charAt(0).toUpperCase() + status?.slice(1)}
      </Badge>
    );
  };

  const getUserDetails = async (userId) => {
    try {
      const response = await axios.get(`${API}/admin/users`);
      const user = response.data.find(u => u.id === userId);
      
      // If user is store owner, get their store rating
      if (user && user.role === 'store_owner') {
        try {
          const storesResponse = await axios.get(`${API}/admin/stores`);
          const userStore = storesResponse.data.find(s => s.owner_id === userId);
          user.store_rating = userStore ? userStore.average_rating : null;
        } catch (error) {
          console.log('Error fetching store rating:', error);
        }
      }
      
      setSelectedUserDetails(user);
    } catch (error) {
      toast.error('Failed to fetch user details');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-3xl font-bold text-gray-900" data-testid="admin-dashboard-title">System Administrator Dashboard</h1>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="mb-8">
            <TabsTrigger value="overview" data-testid="overview-tab">Overview</TabsTrigger>
            <TabsTrigger value="users" data-testid="users-tab">Users</TabsTrigger>
            <TabsTrigger value="stores" data-testid="stores-tab">Stores</TabsTrigger>
          </TabsList>

          <TabsContent value="overview">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
              <Card className="bg-gradient-to-r from-blue-500 to-blue-600 text-white">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-blue-100">Total Users</p>
                      <p className="text-3xl font-bold" data-testid="total-users">{stats.total_users}</p>
                    </div>
                    <Users className="h-8 w-8 text-blue-200" />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-gradient-to-r from-green-500 to-green-600 text-white">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-green-100">Total Stores</p>
                      <p className="text-3xl font-bold" data-testid="total-stores">{stats.total_stores}</p>
                    </div>
                    <Store className="h-8 w-8 text-green-200" />
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-gradient-to-r from-purple-500 to-purple-600 text-white">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-purple-100">Total Ratings</p>
                      <p className="text-3xl font-bold" data-testid="total-ratings">{stats.total_ratings}</p>
                    </div>
                    <TrendingUp className="h-8 w-8 text-purple-200" />
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="users">
            <Card>
              <CardHeader>
                <div className="flex justify-between items-center">
                  <div>
                    <CardTitle>User Management</CardTitle>
                    <CardDescription>Manage all users in the system</CardDescription>
                  </div>
                  <Button 
                    onClick={() => setShowAddUserDialog(true)}
                    className="bg-blue-600 hover:bg-blue-700"
                    data-testid="add-user-btn"
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Add User
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                {/* Filters */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6 p-4 bg-gray-50 rounded-lg">
                  <Input
                    placeholder="Filter by name..."
                    value={userFilters.name}
                    onChange={(e) => setUserFilters({...userFilters, name: e.target.value})}
                    data-testid="user-name-filter"
                  />
                  <Input
                    placeholder="Filter by email..."
                    value={userFilters.email}
                    onChange={(e) => setUserFilters({...userFilters, email: e.target.value})}
                    data-testid="user-email-filter"
                  />
                  <Input
                    placeholder="Filter by address..."
                    value={userFilters.address}
                    onChange={(e) => setUserFilters({...userFilters, address: e.target.value})}
                    data-testid="user-address-filter"
                  />
                  <Select value={userFilters.role} onValueChange={(value) => setUserFilters({...userFilters, role: value})}>
                    <SelectTrigger data-testid="user-role-filter">
                      <SelectValue placeholder="Filter by role..." />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="">All Roles</SelectItem>
                      <SelectItem value="system_admin">System Admin</SelectItem>
                      <SelectItem value="normal_user">Normal User</SelectItem>
                      <SelectItem value="store_owner">Store Owner</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-4">
                  {users.map((user) => (
                    <div key={user.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50">
                      <div className="flex items-center space-x-4">
                        <div className="bg-blue-100 p-2 rounded-full">
                          <User className="h-5 w-5 text-blue-600" />
                        </div>
                        <div>
                          <h3 className="font-semibold">{user.name}</h3>
                          <p className="text-sm text-gray-600 flex items-center">
                            <Mail className="h-4 w-4 mr-1" />
                            {user.email}
                          </p>
                          <p className="text-sm text-gray-600 flex items-center">
                            <MapPin className="h-4 w-4 mr-1" />
                            {user.address}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Badge variant="secondary">
                          {user.role.replace('_', ' ').toUpperCase()}
                        </Badge>
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={() => getUserDetails(user.id)}
                          data-testid={`view-user-${user.id}`}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="stores">
            <Card>
              <CardHeader>
                <CardTitle>Store Management</CardTitle>
                <CardDescription>Manage store approvals and listings</CardDescription>
              </CardHeader>
              <CardContent>
                {/* Store Filters */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6 p-4 bg-gray-50 rounded-lg">
                  <Input
                    placeholder="Filter by store name..."
                    value={storeFilters.name}
                    onChange={(e) => setStoreFilters({...storeFilters, name: e.target.value})}
                    data-testid="store-name-filter"
                  />
                  <Input
                    placeholder="Filter by email..."
                    value={storeFilters.email}
                    onChange={(e) => setStoreFilters({...storeFilters, email: e.target.value})}
                    data-testid="store-email-filter"
                  />
                  <Input
                    placeholder="Filter by address..."
                    value={storeFilters.address}
                    onChange={(e) => setStoreFilters({...storeFilters, address: e.target.value})}
                    data-testid="store-address-filter"
                  />
                </div>

                <div className="space-y-4">
                  {stores.map((store) => (
                    <div key={store.id} className="flex items-center justify-between p-4 border rounded-lg hover:bg-gray-50">
                      <div className="flex items-center space-x-4">
                        <div className="bg-green-100 p-2 rounded-full">
                          <Store className="h-5 w-5 text-green-600" />
                        </div>
                        <div>
                          <h3 className="font-semibold">{store.name}</h3>
                          <p className="text-sm text-gray-600 flex items-center">
                            <Mail className="h-4 w-4 mr-1" />
                            {store.email}
                          </p>
                          <p className="text-sm text-gray-600 flex items-center">
                            <MapPin className="h-4 w-4 mr-1" />
                            {store.address}
                          </p>
                          <div className="flex items-center mt-2">
                            <Star className="h-4 w-4 text-yellow-500 mr-1" />
                            <span className="text-sm">Rating: {store.average_rating.toFixed(1)} ({store.total_ratings} ratings)</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        {getStatusBadge(store.status)}
                        {store.status === 'pending' && (
                          <div className="flex space-x-2">
                            <Button 
                              size="sm" 
                              className="bg-green-600 hover:bg-green-700"
                              onClick={() => approveStore(store.id)}
                              data-testid={`approve-store-${store.id}`}
                            >
                              <Check className="h-4 w-4" />
                            </Button>
                            <Button 
                              size="sm" 
                              variant="destructive"
                              onClick={() => rejectStore(store.id)}
                              data-testid={`reject-store-${store.id}`}
                            >
                              <X className="h-4 w-4" />
                            </Button>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {/* Add User Dialog */}
        <Dialog open={showAddUserDialog} onOpenChange={setShowAddUserDialog}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Add New User</DialogTitle>
              <DialogDescription>Create a new user account with specified role</DialogDescription>
            </DialogHeader>
            <form onSubmit={handleAddUser} className="space-y-4">
              <div className="space-y-2">
                <Label>Full Name (20-60 characters)</Label>
                <Input
                  value={addUserForm.name}
                  onChange={(e) => setAddUserForm({...addUserForm, name: e.target.value})}
                  placeholder="Enter full name"
                  required
                  data-testid="add-user-name"
                />
              </div>
              <div className="space-y-2">
                <Label>Email Address</Label>
                <Input
                  type="email"
                  value={addUserForm.email}
                  onChange={(e) => setAddUserForm({...addUserForm, email: e.target.value})}
                  placeholder="Enter email"
                  required
                  data-testid="add-user-email"
                />
              </div>
              <div className="space-y-2">
                <Label>Password (8-16 chars, 1 uppercase, 1 special)</Label>
                <Input
                  type="password"
                  value={addUserForm.password}
                  onChange={(e) => setAddUserForm({...addUserForm, password: e.target.value})}
                  placeholder="Enter password"
                  required
                  data-testid="add-user-password"
                />
              </div>
              <div className="space-y-2">
                <Label>Address (Max 400 characters)</Label>
                <Textarea
                  value={addUserForm.address}
                  onChange={(e) => setAddUserForm({...addUserForm, address: e.target.value})}
                  placeholder="Enter address"
                  required
                  data-testid="add-user-address"
                />
              </div>
              <div className="space-y-2">
                <Label>User Role</Label>
                <Select value={addUserForm.role} onValueChange={(value) => setAddUserForm({...addUserForm, role: value})}>
                  <SelectTrigger data-testid="add-user-role">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="normal_user">Normal User</SelectItem>
                    <SelectItem value="system_admin">System Admin</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex space-x-2">
                <Button type="submit" className="flex-1" data-testid="submit-add-user">
                  Add User
                </Button>
                <Button type="button" variant="outline" onClick={() => setShowAddUserDialog(false)}>
                  Cancel
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>

        {/* User Details Dialog */}
        <Dialog open={!!selectedUserDetails} onOpenChange={() => setSelectedUserDetails(null)}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>User Details</DialogTitle>
            </DialogHeader>
            {selectedUserDetails && (
              <div className="space-y-4">
                <div>
                  <Label className="font-semibold">Name:</Label>
                  <p className="text-gray-700">{selectedUserDetails.name}</p>
                </div>
                <div>
                  <Label className="font-semibold">Email:</Label>
                  <p className="text-gray-700">{selectedUserDetails.email}</p>
                </div>
                <div>
                  <Label className="font-semibold">Address:</Label>
                  <p className="text-gray-700">{selectedUserDetails.address}</p>
                </div>
                <div>
                  <Label className="font-semibold">Role:</Label>
                  <Badge variant="secondary" className="ml-2">
                    {selectedUserDetails.role.replace('_', ' ').toUpperCase()}
                  </Badge>
                </div>
                {selectedUserDetails.role === 'store_owner' && selectedUserDetails.store_rating !== undefined && (
                  <div>
                    <Label className="font-semibold">Store Rating:</Label>
                    <div className="flex items-center mt-1">
                      <Star className="h-4 w-4 text-yellow-500 mr-1" />
                      <span className="text-gray-700">{selectedUserDetails.store_rating ? selectedUserDetails.store_rating.toFixed(1) : 'No ratings yet'}</span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
};

// Normal User Dashboard
const UserDashboard = () => {
  const [stores, setStores] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [userRatings, setUserRatings] = useState({});

  useEffect(() => {
    fetchStores();
  }, []);

  const fetchStores = async () => {
    try {
      const response = await axios.get(`${API}/stores`);
      setStores(response.data);
      
      // Fetch user's ratings for each store
      const ratings = {};
      for (const store of response.data) {
        try {
          const ratingRes = await axios.get(`${API}/ratings/my-rating/${store.id}`);
          ratings[store.id] = ratingRes.data.rating;
        } catch (error) {
          ratings[store.id] = null;
        }
      }
      setUserRatings(ratings);
    } catch (error) {
      toast.error('Failed to fetch stores');
    }
    setLoading(false);
  };

  const submitRating = async (storeId, rating) => {
    try {
      await axios.post(`${API}/ratings`, {
        store_id: storeId,
        rating: rating
      });
      toast.success('Rating submitted successfully');
      
      // Update local state
      setUserRatings(prev => ({ ...prev, [storeId]: rating }));
      
      // Refresh stores to get updated average rating
      fetchStores();
    } catch (error) {
      toast.error('Failed to submit rating');
    }
  };

  const renderStars = (rating, onStarClick = null, readonly = false) => {
    return (
      <div className="flex">
        {[1, 2, 3, 4, 5].map((star) => (
          <Star
            key={star}
            className={`h-5 w-5 ${
              star <= rating ? 'text-yellow-500 fill-current' : 'text-gray-300'
            } ${!readonly ? 'cursor-pointer hover:text-yellow-400' : ''}`}
            onClick={() => !readonly && onStarClick && onStarClick(star)}
          />
        ))}
      </div>
    );
  };

  const filteredStores = stores.filter(store =>
    store.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    store.address.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-3xl font-bold text-gray-900" data-testid="user-dashboard-title">Store Directory</h1>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-5 w-5" />
            <Input
              placeholder="Search stores by name or address..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 h-12"
              data-testid="store-search"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredStores.map((store) => (
            <Card key={store.id} className="hover:shadow-lg transition-shadow">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>{store.name}</span>
                  <div className="flex items-center">
                    <Star className="h-4 w-4 text-yellow-500 mr-1" />
                    <span className="text-sm">{store.average_rating.toFixed(1)}</span>
                  </div>
                </CardTitle>
                <CardDescription>
                  <div className="flex items-center">
                    <MapPin className="h-4 w-4 mr-1" />
                    {store.address}
                  </div>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <p className="text-sm font-medium mb-2">Store Rating:</p>
                    {renderStars(store.average_rating, null, true)}
                    <p className="text-xs text-gray-500 mt-1">{store.total_ratings} ratings</p>
                  </div>
                  
                  <div>
                    <p className="text-sm font-medium mb-2">
                      Your Rating:
                      {userRatings[store.id] && (
                        <span className="ml-2 text-blue-600">({userRatings[store.id]} stars)</span>
                      )}
                    </p>
                    {renderStars(
                      userRatings[store.id] || 0, 
                      (rating) => submitRating(store.id, rating)
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {filteredStores.length === 0 && (
          <div className="text-center py-12">
            <Store className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No stores found</h3>
            <p className="text-gray-600">Try adjusting your search criteria</p>
          </div>
        )}
      </div>
    </div>
  );
};

// Store Owner Dashboard
const StoreOwnerDashboard = () => {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const { user } = useAuth();

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get(`${API}/store-owner/dashboard`);
      setDashboardData(response.data);
    } catch (error) {
      toast.error('Failed to fetch dashboard data');
    }
    setLoading(false);
  };

  const renderStars = (rating) => {
    return (
      <div className="flex">
        {[1, 2, 3, 4, 5].map((star) => (
          <Star
            key={star}
            className={`h-4 w-4 ${
              star <= rating ? 'text-yellow-500 fill-current' : 'text-gray-300'
            }`}
          />
        ))}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-green-600"></div>
      </div>
    );
  }

  if (!dashboardData || !dashboardData.store) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <h1 className="text-3xl font-bold text-gray-900" data-testid="store-owner-dashboard-title">Store Owner Dashboard</h1>
          </div>
        </div>
        
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Card className="max-w-2xl mx-auto">
            <CardContent className="text-center p-8">
              <Store className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-gray-700 mb-2">No Store Found</h2>
              <p className="text-gray-600 mb-4">
                Your store registration is either pending approval or not found.
              </p>
              <p className="text-sm text-gray-500">
                Please contact the administrator if you believe this is an error.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const { store, users_who_rated, average_rating, total_ratings } = dashboardData;

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <h1 className="text-3xl font-bold text-gray-900" data-testid="store-owner-dashboard-title">Store Owner Dashboard</h1>
        </div>
      </div>
      
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Store Information Card */}
          <div className="lg:col-span-2">
            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span className="flex items-center">
                    <Store className="h-6 w-6 mr-2 text-green-600" />
                    {store.name}
                  </span>
                  <Badge className={`${
                    store.status === 'approved' ? 'bg-green-100 text-green-800' :
                    store.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-red-100 text-red-800'
                  }`}>
                    {store.status.charAt(0).toUpperCase() + store.status.slice(1)}
                  </Badge>
                </CardTitle>
                <CardDescription>
                  <div className="flex items-center mt-2">
                    <Mail className="h-4 w-4 mr-2" />
                    {store.email}
                  </div>
                  <div className="flex items-center mt-1">
                    <MapPin className="h-4 w-4 mr-2" />
                    {store.address}
                  </div>
                </CardDescription>
              </CardHeader>
            </Card>

            {/* Customer Ratings */}
            <Card>
              <CardHeader>
                <CardTitle>Customer Ratings</CardTitle>
                <CardDescription>
                  Users who have rated your store
                </CardDescription>
              </CardHeader>
              <CardContent>
                {users_who_rated && users_who_rated.length > 0 ? (
                  <div className="space-y-4">
                    {users_who_rated.map((user) => (
                      <div key={user.id} className="flex items-center justify-between p-4 border rounded-lg bg-gray-50">
                        <div className="flex items-center space-x-4">
                          <div className="bg-blue-100 p-2 rounded-full">
                            <User className="h-5 w-5 text-blue-600" />
                          </div>
                          <div>
                            <h3 className="font-semibold">{user.name}</h3>
                            <p className="text-sm text-gray-600 flex items-center">
                              <Mail className="h-4 w-4 mr-1" />
                              {user.email}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <Star className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 mb-2">No ratings yet</h3>
                    <p className="text-gray-600">Once customers start rating your store, they'll appear here.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Statistics Sidebar */}
          <div className="space-y-6">
            
            {/* Rating Overview */}
            <Card className="bg-gradient-to-r from-green-500 to-emerald-600 text-white">
              <CardContent className="p-6">
                <div className="text-center">
                  <h3 className="text-lg font-medium text-green-100 mb-2">Your Store Rating</h3>
                  <div className="text-4xl font-bold mb-3" data-testid="store-average-rating">
                    {average_rating.toFixed(1)}
                  </div>
                  <div className="flex justify-center mb-2">
                    {renderStars(average_rating)}
                  </div>
                  <p className="text-green-100" data-testid="store-total-ratings">
                    Based on {total_ratings} {total_ratings === 1 ? 'rating' : 'ratings'}
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Quick Stats */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <TrendingUp className="h-5 w-5 mr-2 text-blue-600" />
                  Quick Stats
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-gray-600">Total Ratings:</span>
                  <span className="font-bold text-lg" data-testid="total-ratings-count">{total_ratings}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-gray-600">Average Rating:</span>
                  <span className="font-bold text-lg text-green-600">{average_rating.toFixed(1)}/5</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm font-medium text-gray-600">Store Status:</span>
                  <Badge variant={store.status === 'approved' ? 'default' : 'secondary'}>
                    {store.status.charAt(0).toUpperCase() + store.status.slice(1)}
                  </Badge>
                </div>
              </CardContent>
            </Card>

            {/* Rating Breakdown */}
            {total_ratings > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Rating Performance</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {[5, 4, 3, 2, 1].map((rating) => (
                      <div key={rating} className="flex items-center space-x-2">
                        <span className="text-sm w-4">{rating}</span>
                        <Star className="h-3 w-3 text-yellow-500" />
                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                          <div 
                            className="bg-yellow-500 h-2 rounded-full"
                            style={{ 
                              width: average_rating === rating ? '100%' : '0%' 
                            }}
                          ></div>
                        </div>
                        <span className="text-sm text-gray-600 w-8">
                          {average_rating === rating ? '1' : '0'}
                        </span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

          </div>
        </div>
      </div>
    </div>
  );
};
const Header = () => {
  const { user, logout } = useAuth();

  return (
    <header className="bg-white shadow-sm border-b">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center py-4">
          <div className="flex items-center">
            <h2 className="text-xl font-semibold text-gray-800">
              Welcome, {user?.name}
            </h2>
            <Badge variant="secondary" className="ml-3">
              {user?.role?.replace('_', ' ').toUpperCase()}
            </Badge>
          </div>
          <Button 
            onClick={logout} 
            variant="outline"
            className="flex items-center space-x-2"
            data-testid="logout-button"
          >
            <LogOut className="h-4 w-4" />
            <span>Logout</span>
          </Button>
        </div>
      </div>
    </header>
  );
};

// Protected Route Component
const ProtectedRoute = ({ children, allowedRoles }) => {
  const { user, token, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!token || !user) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/unauthorized" replace />;
  }

  return (
    <>
      <Header />
      {children}
    </>
  );
};

// Main App Component
function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <div className="App">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/store-register" element={<StoreOwnerRegister />} />
            
            <Route path="/admin" element={
              <ProtectedRoute allowedRoles={['system_admin']}>
                <AdminDashboard />
              </ProtectedRoute>
            } />
            
            <Route path="/dashboard" element={
              <ProtectedRoute allowedRoles={['normal_user']}>
                <UserDashboard />
              </ProtectedRoute>
            } />
            
            <Route path="/store-dashboard" element={
              <ProtectedRoute allowedRoles={['store_owner']}>
                <StoreOwnerDashboard />
              </ProtectedRoute>
            } />
            
            <Route path="/unauthorized" element={
              <div className="min-h-screen flex items-center justify-center bg-red-50">
                <Card className="max-w-md">
                  <CardContent className="text-center p-6">
                    <AlertCircle className="h-16 w-16 text-red-500 mx-auto mb-4" />
                    <h2 className="text-2xl font-bold text-red-700 mb-2">Access Denied</h2>
                    <p className="text-red-600">You don't have permission to access this page.</p>
                  </CardContent>
                </Card>
              </div>
            } />
            
            <Route path="/" element={
              <Navigate to={
                localStorage.getItem('token') ? '/dashboard' : '/login'
              } replace />
            } />
          </Routes>
          
          <Toaster position="top-right" richColors />
        </div>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;