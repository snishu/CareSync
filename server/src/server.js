const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
app.use(cors({ origin: process.env.CLIENT_URL || 'http://localhost:5173' }));
app.use(express.json());

const taskSchema = new mongoose.Schema({
  title:{type:String,required:true,trim:true},
  description:{type:String,default:''},
  dueDate:{type:String,default:''},
  priority:{type:String,enum:['Low','Medium','High'],default:'Medium'},
  completed:{type:Boolean,default:false},
  reminderAt:{type:String,default:''},
  reminderEnabled:{type:Boolean,default:false},
  repeat:{type:String,enum:['Once','Daily','Weekly'],default:'Once'},
  alarmSound:{type:Boolean,default:true},
  parentAlert:{type:Boolean,default:false}
},{timestamps:true});

const medicineSchema = new mongoose.Schema({
  name:{type:String,required:true,trim:true},
  dosage:{type:String,default:''},
  time:{type:String,required:true},
  frequency:{type:String,default:'Daily'},
  active:{type:Boolean,default:true},
  alarmEnabled:{type:Boolean,default:true}
},{timestamps:true});

const userSchema = new mongoose.Schema({
  name:{type:String,required:true,trim:true},
  email:{type:String,required:true,unique:true,lowercase:true,trim:true},
  phone:{type:String,default:''},
  password:{type:String,required:true},
  familyCode:{type:String,default:''},
  tasks:[taskSchema],
  medicines:[medicineSchema]
},{timestamps:true});

const User = mongoose.model('User',userSchema);
const familyAlertSchema = new mongoose.Schema({
  familyCode:{type:String,required:true,index:true},
  senderName:{type:String,required:true},
  title:{type:String,required:true},
  detail:{type:String,default:''},
  createdAt:{type:Date,default:Date.now},
  acknowledgedBy:{type:[String],default:[]}
},{timestamps:true});
const FamilyAlert = mongoose.model('FamilyAlert',familyAlertSchema);
function makeFamilyCode(){return Math.random().toString(36).slice(2,8).toUpperCase();}

function signToken(user){return jwt.sign({id:user._id.toString()},process.env.JWT_SECRET,{expiresIn:'7d'});}
function auth(req,res,next){
  const h=req.headers.authorization||'';
  const token=h.startsWith('Bearer ')?h.slice(7):'';
  if(!token) return res.status(401).json({message:'Authentication required'});
  try{req.userId=jwt.verify(token,process.env.JWT_SECRET).id;next();}
  catch(e){return res.status(401).json({message:'Session expired. Please sign in again.'});}
}
function cleanUser(u){return {id:u._id,name:u.name,email:u.email,phone:u.phone,familyCode:u.familyCode,tasks:u.tasks,medicines:u.medicines};}

app.get('/api/health',(req,res)=>res.json({ok:true,service:'CareSync'}));

app.post('/api/auth/signup',async(req,res)=>{
  try{
    const {name,email,phone,password}=req.body;
    if(!name||!email||!password) return res.status(400).json({message:'Name, email and password are required.'});
    if(password.length<8) return res.status(400).json({message:'Password must be at least 8 characters.'});
    const normalized=email.trim().toLowerCase();
    const exists=await User.findOne({email:normalized});
    if(exists) return res.status(409).json({message:'Email is already registered.'});
    const hash=await bcrypt.hash(password,12);
    const user=await User.create({name:name.trim(),email:normalized,phone:(phone||'').trim(),password:hash,familyCode:makeFamilyCode()});
    res.status(201).json({token:signToken(user),user:cleanUser(user)});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to create account.'});}
});

app.post('/api/auth/login',async(req,res)=>{
  try{
    const {email,password}=req.body;
    const user=await User.findOne({email:String(email||'').trim().toLowerCase()});
    if(!user || !(await bcrypt.compare(password||'',user.password))) return res.status(401).json({message:'Invalid email or password.'});
    res.json({token:signToken(user),user:cleanUser(user)});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to sign in.'});}
});

app.post('/api/auth/delete-account',async(req,res)=>{
  try{
    const {email,phone,confirmation}=req.body;
    if(confirmation!=='DELETE MY DATA') return res.status(400).json({message:'Type DELETE MY DATA exactly to confirm.'});
    const user=await User.findOne({email:String(email||'').trim().toLowerCase(),phone:String(phone||'').trim()});
    if(!user) return res.status(404).json({message:'No matching account found. Check your email and phone number.'});
    await User.deleteOne({_id:user._id});
    res.json({message:'Account and all associated CareSync data have been permanently deleted.'});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to delete account data.'});}
});

app.get('/api/family',auth,async(req,res)=>{
  try{
    const u=await User.findById(req.userId);
    if(!u)return res.status(404).json({message:'User not found'});
    if(!u.familyCode){u.familyCode=makeFamilyCode();await u.save();}
    const members=await User.find({familyCode:u.familyCode}).select('_id name email');
    const alerts=u.familyCode?await FamilyAlert.find({familyCode:u.familyCode}).sort({createdAt:-1}).limit(20):[];
    res.json({familyCode:u.familyCode,members,alerts});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to load family workspace.'});}
});

app.post('/api/family/join',auth,async(req,res)=>{
  try{
    const code=String(req.body.code||'').trim().toUpperCase();
    if(!/^[A-Z0-9]{6}$/.test(code))return res.status(400).json({message:'Enter a valid 6-character family code.'});
    const u=await User.findById(req.userId);
    const exists=await User.findOne({familyCode:code});
    if(!exists)return res.status(404).json({message:'Family code not found.'});
    u.familyCode=code;await u.save();
    res.json({message:'Joined family workspace.',familyCode:code});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to join family workspace.'});}
});

app.post('/api/family/alerts',auth,async(req,res)=>{
  try{
    const u=await User.findById(req.userId);
    if(!u?.familyCode)return res.status(400).json({message:'Join a family workspace first.'});
    const title=String(req.body.title||'').trim();
    if(!title)return res.status(400).json({message:'Alert title is required.'});
    const alert=await FamilyAlert.create({familyCode:u.familyCode,senderName:u.name,title,detail:String(req.body.detail||'')});
    res.status(201).json({alert});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to create family alert.'});}
});

app.post('/api/family/alerts/:id/ack',auth,async(req,res)=>{
  try{
    const alert=await FamilyAlert.findById(req.params.id);
    if(!alert)return res.status(404).json({message:'Alert not found.'});
    const u=await User.findById(req.userId);
    if(!u||u.familyCode!==alert.familyCode)return res.status(403).json({message:'Not part of this family workspace.'});
    if(!alert.acknowledgedBy.includes(String(u._id)))alert.acknowledgedBy.push(String(u._id));
    await alert.save();res.json({message:'Alert acknowledged.'});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to acknowledge alert.'});}
});

app.get('/api/me',auth,async(req,res)=>{
  const u=await User.findById(req.userId);
  if(!u)return res.status(404).json({message:'User not found'});
  res.json({user:cleanUser(u)});
});

app.post('/api/tasks',auth,async(req,res)=>{
  try{
    const {title,description,dueDate,priority,reminderAt,reminderEnabled,repeat,alarmSound,parentAlert}=req.body;
    if(!title?.trim()) return res.status(400).json({message:'Task title is required.'});
    const u=await User.findById(req.userId);
    u.tasks.push({title:title.trim(),description:description||'',dueDate:dueDate||'',priority:priority||'Medium',reminderAt:reminderAt||'',reminderEnabled:Boolean(reminderEnabled),repeat:repeat||'Once',alarmSound:alarmSound!==false,parentAlert:Boolean(parentAlert)});
    await u.save();
    res.status(201).json({task:u.tasks[u.tasks.length-1]});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to create task.'});}
});

app.patch('/api/tasks/:id',auth,async(req,res)=>{
  try{
    const u=await User.findById(req.userId);const t=u.tasks.id(req.params.id);
    if(!t)return res.status(404).json({message:'Task not found'});
    const allowed=['title','description','dueDate','priority','completed','reminderAt','reminderEnabled','repeat','alarmSound','parentAlert'];
    allowed.forEach(k=>{if(req.body[k]!==undefined)t[k]=req.body[k];});
    await u.save();res.json({task:t});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to update task.'});}
});

app.delete('/api/tasks/:id',auth,async(req,res)=>{
  try{
    const password=String(req.body?.password||'');
    if(!password)return res.status(400).json({message:'Current password is required to delete a task.'});
    const u=await User.findById(req.userId);
    if(!u)return res.status(404).json({message:'User not found'});
    const valid=await bcrypt.compare(password,u.password);
    if(!valid)return res.status(401).json({message:'Incorrect password. Task was not deleted.'});
    const t=u.tasks.id(req.params.id);
    if(!t)return res.status(404).json({message:'Task not found'});
    t.deleteOne();await u.save();res.json({message:'Task deleted'});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to delete task.'});}
});

app.post('/api/medicines',auth,async(req,res)=>{
  try{
    const {name,dosage,time,frequency,alarmEnabled}=req.body;
    if(!name?.trim()||!time)return res.status(400).json({message:'Medicine name and time are required.'});
    const u=await User.findById(req.userId);
    u.medicines.push({name:name.trim(),dosage:dosage||'',time,frequency:frequency||'Daily',alarmEnabled:alarmEnabled!==false});
    await u.save();res.status(201).json({medicine:u.medicines[u.medicines.length-1]});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to create medicine reminder.'});}
});

app.patch('/api/medicines/:id',auth,async(req,res)=>{
  try{
    const u=await User.findById(req.userId);const m=u.medicines.id(req.params.id);
    if(!m)return res.status(404).json({message:'Medicine not found'});
    ['name','dosage','time','frequency','active','alarmEnabled'].forEach(k=>{if(req.body[k]!==undefined)m[k]=req.body[k];});
    await u.save();res.json({medicine:m});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to update medicine reminder.'});}
});

app.delete('/api/medicines/:id',auth,async(req,res)=>{
  try{
    const u=await User.findById(req.userId);const m=u.medicines.id(req.params.id);
    if(!m)return res.status(404).json({message:'Medicine not found'});
    m.deleteOne();await u.save();res.json({message:'Medicine deleted'});
  }catch(e){console.error(e);res.status(500).json({message:'Unable to delete medicine.'});}
});

const PORT=process.env.PORT||5000;
if(!process.env.MONGO_URI){console.error('MONGO_URI is missing in server/.env');process.exit(1);}
if(!process.env.JWT_SECRET){console.error('JWT_SECRET is missing in server/.env');process.exit(1);}
mongoose.connect(process.env.MONGO_URI).then(()=>app.listen(PORT,()=>console.log(`CareSync API running on http://localhost:${PORT}`))).catch(e=>{console.error('MongoDB connection failed:',e.message);process.exit(1);});
